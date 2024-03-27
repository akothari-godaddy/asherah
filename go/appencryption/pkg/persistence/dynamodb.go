package persistence

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	"github.com/godaddy/asherah/go/appencryption"
	"github.com/pkg/errors"
	"github.com/rcrowley/go-metrics"
)

const (
	defaultTableName = "EncryptionKey"
	partitionKey     = "Id"
	sortKey          = "Created"
	keyRecord        = "KeyRecord"
)

var (
	// Verify DynamoDBMetastore implements the Metastore interface.
	_ appencryption.Metastore = (*DynamoDBMetastore)(nil)

	// DynamoDB metastore metrics
	loadDynamoDBTimer       = metrics.GetOrRegisterTimer(fmt.Sprintf("%s.metastore.dynamodb.load", appencryption.MetricsPrefix), nil)
	loadLatestDynamoDBTimer = metrics.GetOrRegisterTimer(fmt.Sprintf("%s.metastore.dynamodb.loadlatest", appencryption.MetricsPrefix), nil)
	storeDynamoDBTimer      = metrics.GetOrRegisterTimer(fmt.Sprintf("%s.metastore.dynamodb.store", appencryption.MetricsPrefix), nil)
)

// DynamoDBMetastore implements the Metastore interface.
type DynamoDBMetastore struct {
	svc          *dynamodb.Client
	regionSuffix string
	tableName    string
}

// GetRegionSuffix returns the DynamoDB region suffix or blank if not configured.
func (d *DynamoDBMetastore) GetRegionSuffix() string {
	return d.regionSuffix
}

// GetTableName returns the DynamoDB table name.
func (d *DynamoDBMetastore) GetTableName() string {
	return d.tableName
}

// DynamoDBMetastoreOption configures options for DynamoDBMetastore.
type DynamoDBMetastoreOption func(*DynamoDBMetastore)

// WithDynamoDBRegionSuffix configures the DynamoDBMetastore to use a regional suffix for
// all writes. This feature should be enabled when using DynamoDB global tables to avoid
// write conflicts arising from the "last writer wins" method of conflict resolution.
// WithDynamoDBRegionSuffix specifies the DynamoDB region suffix for the metastore.
func WithDynamoDBRegionSuffix(suffix string) DynamoDBMetastoreOption {
	return func(d *DynamoDBMetastore) {
		d.regionSuffix = suffix
	}
}

// WithTableName specifies the table name for the metastore.
func WithTableName(tableName string) DynamoDBMetastoreOption {
	return func(d *DynamoDBMetastore) {
		if tableName != "" {
			d.tableName = tableName
		}
	}
}

func NewDynamoDBMetastore(cfg *aws.Config, opts ...DynamoDBMetastoreOption) *DynamoDBMetastore {
	d := &DynamoDBMetastore{
		svc:       dynamodb.NewFromConfig(*cfg),
		tableName: defaultTableName,
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

func parseResult(item map[string]types.AttributeValue) (*appencryption.EnvelopeKeyRecord, error) {
	var record appencryption.EnvelopeKeyRecord
	err := attributevalue.UnmarshalMap(item, &record)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal DynamoDB item to EnvelopeKeyRecord")
	}

	return &record, nil
}

// Load retrieves the envelope key record for the given keyID and created time.
func (d *DynamoDBMetastore) Load(ctx context.Context, keyID string, created int64) (*appencryption.EnvelopeKeyRecord, error) {
	defer loadDynamoDBTimer.UpdateSince(time.Now())

	key := map[string]types.AttributeValue{
		partitionKey: &types.AttributeValueMemberS{Value: keyID},
		sortKey:      &types.AttributeValueMemberN{Value: strconv.FormatInt(created, 10)},
	}

	out, err := d.svc.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.tableName,
		Key:            key,
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to load item from DynamoDB")
	}

	if out.Item == nil {
		return nil, nil // Not found
	}

	return parseResult(out.Item)
}

// LoadLatest returns the newest record matching the keyID.
// The return value will be nil if not already present.
func (d *DynamoDBMetastore) LoadLatest(ctx context.Context, keyID string) (*appencryption.EnvelopeKeyRecord, error) {
	defer loadLatestDynamoDBTimer.UpdateSince(time.Now())

	// Define the key condition for querying by partition key (keyID)
	keyCond := expression.Key(partitionKey).Equal(expression.Value(keyID))

	// Define the projection to include only the 'KeyRecord' attribute
	proj := expression.NamesList(expression.Name(keyRecord))
	// Build the expression
	expr, err := expression.NewBuilder().WithKeyCondition(keyCond).WithProjection(proj).Build()
	if err != nil {
		return nil, errors.Wrap(err, "dynamodb expression error")
	}

	// Execute the query
	res, err := d.svc.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(d.tableName),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
		ScanIndexForward:          aws.Bool(false), // Ensure we're scanning in reverse order
		Limit:                     aws.Int32(1),    // We only want the latest (most recent) record
		ConsistentRead:            aws.Bool(true),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if err != nil {
		return nil, err
	}

	if len(res.Items) == 0 {
		return nil, nil
	}

	// Parse the result
	return parseResult(res.Items[0])
}

// DynamoDBEnvelope is used to convert the EncryptedKey to a Base64 encoded string
// to save in DynamoDB.
type DynamoDBEnvelope struct {
	Revoked       bool                   `json:"Revoked,omitempty"`
	Created       int64                  `json:"Created"`
	EncryptedKey  string                 `json:"Key"`
	ParentKeyMeta *appencryption.KeyMeta `json:"ParentKeyMeta,omitempty"`
}

// Store attempts to insert the key into the metastore if one is not
// already present. If a key exists, the method will return false. If
// one is not present, the value will be inserted and we return true.
func (d *DynamoDBMetastore) Store(ctx context.Context, keyID string, created int64, envelope *appencryption.EnvelopeKeyRecord) (bool, error) {
	defer storeDynamoDBTimer.UpdateSince(time.Now())

	// Convert your envelope key record to a DynamoDBEnvelope for storage
	encryptedKeyBase64 := base64.StdEncoding.EncodeToString(envelope.EncryptedKey)
	dynamoEnvelope := DynamoDBEnvelope{
		Revoked:       envelope.Revoked,
		Created:       envelope.Created,
		EncryptedKey:  encryptedKeyBase64,
		ParentKeyMeta: envelope.ParentKeyMeta,
	}

	// Marshal the DynamoDBEnvelope to a DynamoDB attribute value map
	item, err := attributevalue.MarshalMap(dynamoEnvelope)
	if err != nil {
		return false, errors.Wrap(err, "failed to marshal envelope")
	}

	// Prepare the DynamoDB item with additional attributes for partitionKey and sortKey
	item[partitionKey] = &types.AttributeValueMemberS{Value: keyID}
	item[sortKey] = &types.AttributeValueMemberN{Value: strconv.FormatInt(created, 10)}

	// Attempt to store the item using a conditional expression to avoid overwriting existing records
	_, err = d.svc.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.tableName),
		Item:      item,
		// Conditional expression to ensure the item does not already exist
		ConditionExpression: aws.String("attribute_not_exists(" + partitionKey + ") AND attribute_not_exists(" + sortKey + ")"),
	})

	// Handle conditional check failure (i.e., item already exists) separately
	if err != nil {
		var ce *smithy.OperationError
		if errors.As(err, &ce) && ce.Err.Error() == "ConditionalCheckFailedException" {
			return false, nil // Item already exists, return false to indicate no store was made
		}
		// For other errors, wrap and return them
		return false, errors.Wrap(err, "error storing key")
	}

	// If there's no error, the item was successfully stored
	return true, nil
}

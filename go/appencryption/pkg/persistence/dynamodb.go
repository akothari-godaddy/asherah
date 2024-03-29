package persistence

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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

func parseResult(item types.AttributeValue) (*appencryption.EnvelopeKeyRecord, error) {
	var record appencryption.KRecord

	var finalRecord appencryption.EnvelopeKeyRecord
	// output, err := json.MarshalIndent(item, "", "  ")
	// if err != nil {
	// 	log.Fatalf("failed to marshal QueryOutput, %v", err)
	// }
	// // fmt.Println(string(output))

	if mapAttr, ok := item.(*types.AttributeValueMemberM); ok {
		// Now you can access the attributes as a map
		// fmt.Println("mapAttr: ", mapAttr.Value)
		err := attributevalue.UnmarshalMap(mapAttr.Value, &record)
		if err != nil {
			log.Fatalf("failed to unmarshal AttributeValue map to struct: %v", err)
		}
	}

	// Decode the base64-encoded EncryptedKey
	decodedKey, err := base64.StdEncoding.DecodeString(record.Key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode EncryptedKey")
	}

	// fmt.Println("decodedKey: ", string(decodedKey))

	// fmt.Println("record: ", record, record.Revoked)

	finalRecord = appencryption.EnvelopeKeyRecord{EncryptedKey: []byte(decodedKey), Created: record.Created, ParentKeyMeta: record.ParentKeyMeta}

	// fmt.Println("finalRecord: ", finalRecord.ParentKeyMeta)

	return &finalRecord, nil
}

// Load retrieves the envelope key record for the given keyID and created time.
func (d *DynamoDBMetastore) Load(ctx context.Context, keyID string, created int64) (*appencryption.EnvelopeKeyRecord, error) {
	defer loadDynamoDBTimer.UpdateSince(time.Now())

	// fmt.Println("keyID: ", keyID, "created: ", created)
	key := map[string]types.AttributeValue{
		partitionKey: &types.AttributeValueMemberS{Value: keyID},
		sortKey:      &types.AttributeValueMemberN{Value: strconv.FormatInt(created, 10)},
	}

	out, err := d.svc.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.tableName,
		Key:            key,
		ConsistentRead: aws.Bool(true),
	})

	// fmt.Println("load", "out: ", out, out.Item, "err: ", err)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load item from DynamoDB")
	}

	if out.Item == nil {
		return nil, nil // Not found
	}

	return parseResult(out.Item[keyRecord])
}

// LoadLatest returns the newest record matching the keyID.
// The return value will be nil if not already present.
func (d *DynamoDBMetastore) LoadLatest(ctx context.Context, keyID string) (*appencryption.EnvelopeKeyRecord, error) {
	defer loadLatestDynamoDBTimer.UpdateSince(time.Now())

	// fmt.Println("keyID: ", keyID)

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
		return nil, errors.Wrap(err, "failed to query DynamoDB")
	}

	if len(res.Items) == 0 {
		return nil, nil
	}

	// Parse the result
	return parseResult(res.Items[0][keyRecord])
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
	// fmt.Println("Store keyID: ", keyID)
	// Convert your envelope key record to a DynamoDBEnvelope for storage
	en := &DynamoDBEnvelope{
		Revoked:       envelope.Revoked,
		Created:       envelope.Created,
		EncryptedKey:  base64.StdEncoding.EncodeToString(envelope.EncryptedKey),
		ParentKeyMeta: envelope.ParentKeyMeta,
	}

	var record appencryption.KRecord

	record.Key = en.EncryptedKey
	record.Created = en.Created
	record.ParentKeyMeta = en.ParentKeyMeta
	record.Revoked = en.Revoked

	// fmt.Println("Store record: ", record)

	av, err := attributevalue.MarshalMap(record)
	if err != nil {
		return false, fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// Prepare the Item map
	item := map[string]types.AttributeValue{
		partitionKey: &types.AttributeValueMemberS{Value: keyID},                          // Adjust for actual partition key name
		sortKey:      &types.AttributeValueMemberN{Value: strconv.FormatInt(created, 10)}, // Adjust for actual sort key name
		keyRecord:    &types.AttributeValueMemberM{Value: av},                             // 'keyRecord' attribute
	}

	_, err = d.svc.PutItem(ctx, &dynamodb.PutItemInput{
		Item:                item,
		TableName:           aws.String(d.tableName),
		ConditionExpression: aws.String("attribute_not_exists(" + partitionKey + ")"),
	})

	// fmt.Println("store", "item: ", item, "err: ", err)
	var conditionCheckFailedException *types.ConditionalCheckFailedException
	if err != nil {
		if ok := errors.As(err, &conditionCheckFailedException); ok {
			return false, fmt.Errorf("attempted to create duplicate key: %s, %d: %w", keyID, created, err)
		}
		return false, fmt.Errorf("error storing key key: %s, %d: %w", keyID, created, err)
	}

	// If there's no error, the item was successfully stored
	return true, nil
}

package appencryption

import (
	"context"
	"fmt"
	"time"

	"github.com/godaddy/asherah/go/securememory"
	"github.com/pkg/errors"
	"github.com/rcrowley/go-metrics"

	"github.com/godaddy/asherah/go/appencryption/internal"
	"github.com/godaddy/asherah/go/appencryption/pkg/log"
)

// MetricsPrefix prefixes all metrics names
const MetricsPrefix = "ael"

// Envelope metrics
var (
	decryptTimer = metrics.GetOrRegisterTimer(fmt.Sprintf("%s.drr.decrypt", MetricsPrefix), nil)
	encryptTimer = metrics.GetOrRegisterTimer(fmt.Sprintf("%s.drr.encrypt", MetricsPrefix), nil)
)

// KeyMeta contains the ID and Created timestamp for an encryption key.
type KeyMeta struct {
	ID      string `json:"KeyId" dynamodbav:"KeyId"`
	Created int64  `json:"Created" dynamodbav:"Created"`
}

// String returns a string with the KeyMeta values.
func (m KeyMeta) String() string {
	return fmt.Sprintf("KeyMeta [keyId=%s created=%d]", m.ID, m.Created)
}

// IsLatest returns true if the key meta is the latest version of the key.
func (m KeyMeta) IsLatest() bool {
	return m.Created == 0
}

// AsLatest returns a copy of the key meta with the Created timestamp set to 0.
func (m KeyMeta) AsLatest() KeyMeta {
	return KeyMeta{
		ID:      m.ID,
		Created: 0,
	}
}

// DataRowRecord contains the encrypted key and provided data, as well as the information
// required to decrypt the key encryption key. This struct should be stored in your
// data persistence as it's required to decrypt data.
type DataRowRecord struct {
	Key  *EnvelopeKeyRecord
	Data []byte
}

// EnvelopeKeyRecord represents an encrypted key and is the data structure used
// to persist the key in our key table. It also contains the meta data
// of the key used to encrypt it.
type EnvelopeKeyRecord struct {
	Revoked       bool     `json:"Revoked,omitempty"`
	ID            string   `json:"-"`
	Created       int64    `json:"Created"`
	EncryptedKey  []byte   `json:"Key"`
	ParentKeyMeta *KeyMeta `json:"ParentKeyMeta,omitempty"`
}

type KRecord struct {
	Key           string   `dynamodbav:"Key"`
	Created       int64    `dynamodbav:"Created"`
	ParentKeyMeta *KeyMeta `dynamodbav:"ParentKeyMeta"`
	Revoked       bool     `dynamodbav:"Revoked"`
}

// Verify envelopeEncryption implements the Encryption interface.
var _ Encryption = (*envelopeEncryption)(nil)

// envelopeEncryption is used to encrypt and decrypt data related to a specific partition ID.
type envelopeEncryption struct {
	partition     partition
	Metastore     Metastore
	KMS           KeyManagementService
	Policy        *CryptoPolicy
	Crypto        AEAD
	SecretFactory securememory.SecretFactory
	skCache       keyCacher
	ikCache       keyCacher
}

// loadSystemKey fetches a known system key from the metastore and decrypts it using the key management service.
func (e *envelopeEncryption) loadSystemKey(ctx context.Context, meta KeyMeta) (*internal.CryptoKey, error) {
	ekr, err := e.Metastore.Load(ctx, meta.ID, meta.Created)
	if err != nil {
		return nil, err
	}

	if ekr == nil {
		return nil, errors.New("error loading system key from metastore")
	}

	return e.systemKeyFromEKR(ctx, ekr)
}

// systemKeyFromEKR decrypts ekr using the key management service and returns a new CryptoKey containing the decrypted key data.
func (e *envelopeEncryption) systemKeyFromEKR(ctx context.Context, ekr *EnvelopeKeyRecord) (*internal.CryptoKey, error) {
	bytes, err := e.KMS.DecryptKey(ctx, ekr.EncryptedKey)

	if err != nil {
		return nil, err
	}

	return internal.NewCryptoKey(e.SecretFactory, ekr.Created, ekr.Revoked, bytes)
}

type accessorRevokable interface {
	internal.Revokable
	internal.BytesFuncAccessor
}

// intermediateKeyFromEKR decrypts ekr using sk and returns a new CryptoKey containing the decrypted key data.
func (e *envelopeEncryption) intermediateKeyFromEKR(sk accessorRevokable, ekr *EnvelopeKeyRecord) (*internal.CryptoKey, error) {
	if ekr != nil && ekr.ParentKeyMeta != nil && sk.Created() != ekr.ParentKeyMeta.Created {
		// In this case, the system key just rotated and this EKR was encrypted with the prior SK.
		// A duplicate IK would have been attempted to create with the correct SK but would create a duplicate so is discarded.
		// Lookup the correct system key so the ik decryption can succeed.
		skLoaded, err := e.getOrLoadSystemKey(context.Background(), *ekr.ParentKeyMeta)
		if err != nil {
			return nil, err
		}

		sk = skLoaded
	}

	ikBuffer, err := internal.WithKeyFunc(sk, func(skBytes []byte) ([]byte, error) {
		return e.Crypto.Decrypt(ekr.EncryptedKey, skBytes)
	})
	if err != nil {
		return nil, err
	}

	return internal.NewCryptoKey(e.SecretFactory, ekr.Created, ekr.Revoked, ikBuffer)
}

// loadLatestOrCreateSystemKey gets the most recently created system key for the given id or creates a new one.
func (e *envelopeEncryption) loadLatestOrCreateSystemKey(ctx context.Context, id string) (*internal.CryptoKey, error) {
	ekr, err := e.Metastore.LoadLatest(ctx, id)
	if err != nil {
		return nil, err
	}

	if ekr != nil && !e.isEnvelopeInvalid(ekr) {
		// We've retrieved an SK from the store and it's valid, use it.
		return e.systemKeyFromEKR(ctx, ekr)
	}

	// fmt.Println("ekr1")

	// Create a new SK
	sk, err := e.generateKey()
	if err != nil {
		return nil, err
	}

	switch success, err2 := e.tryStoreSystemKey(ctx, sk); {
	case success:
		// New key saved successfully, return it.
		return sk, nil
	default:
		// it's no good to us now. throw it away
		sk.Close()

		if err2 != nil {
			return nil, err2
		}
	}

	// Well, we created a new SK but the store was unsuccessful. Let's assume that's because we
	// attempted to save a duplicate key to the metastore because, if that's the case a new key
	// was added sometime between our load and store attempts, so let's grab it and return it.
	ekr, err = e.mustLoadLatest(ctx, id)
	// fmt.Println("ekr2", string(ekr.EncryptedKey))
	if err != nil {
		// Oops! Looks like our assumption was incorrect and all we can do now is report the error.
		return nil, err
	}

	return e.systemKeyFromEKR(ctx, ekr)
}

// tryStoreSystemKey attempts to persist the encrypted sk to the metastore ignoring all persistence related errors.
// err will be non-nil only if encryption fails.
func (e *envelopeEncryption) tryStoreSystemKey(ctx context.Context, sk *internal.CryptoKey) (success bool, err error) {
	encKey, err := internal.WithKeyFunc(sk, func(keyBytes []byte) ([]byte, error) {
		return e.KMS.EncryptKey(ctx, keyBytes)
	})

	// fmt.Println("tryStoreSystemKey", string(encKey), err)
	if err != nil {
		return false, err
	}

	ekr := &EnvelopeKeyRecord{
		ID:           e.partition.SystemKeyID(),
		Created:      sk.Created(),
		EncryptedKey: encKey,
	}

	return e.tryStore(ctx, ekr), nil
}

// isEnvelopeInvalid checks if the envelope key record is revoked or has an expired key.
func (e *envelopeEncryption) isEnvelopeInvalid(ekr *EnvelopeKeyRecord) bool {
	// TODO Add key rotation policy check. If not inline, then can return valid even if expired
	return e == nil || internal.IsKeyExpired(ekr.Created, e.Policy.ExpireKeyAfter) || ekr.Revoked
}

func (e *envelopeEncryption) generateKey() (*internal.CryptoKey, error) {
	createdAt := newKeyTimestamp(e.Policy.CreateDatePrecision)
	return internal.GenerateKey(e.SecretFactory, createdAt, AES256KeySize)
}

// tryStore attempts to persist the key into the metastore and returns true if successful.
//
// SQL metastore has a limitation where we can't detect duplicate key from other errors,
// so we treat all errors as if they are duplicates. If it's a systemic issue, it
// likely would've already occurred in the previous lookup (or in the next one). Worst case is a
// caller has to retry, which they would have needed to anyway.
func (e *envelopeEncryption) tryStore(
	ctx context.Context,
	ekr *EnvelopeKeyRecord,
) bool {
	success, err := e.Metastore.Store(ctx, ekr.ID, ekr.Created, ekr)

	_ = err // err is intentionally ignored

	return success
}

// mustLoadLatest attempts to load the latest key from the metastore and returns an error if no key is found
// matching id.
func (e *envelopeEncryption) mustLoadLatest(ctx context.Context, id string) (*EnvelopeKeyRecord, error) {
	ekr, err := e.Metastore.LoadLatest(ctx, id)
	if err != nil {
		return nil, err
	}

	if ekr == nil {
		return nil, errors.New("error loading key from metastore after retry")
	}

	return ekr, nil
}

// createIntermediateKey creates a new IK and attempts to persist the new key to the metastore.
// If unsuccessful createIntermediateKey will attempt to fetch the latest IK from the metastore.
func (e *envelopeEncryption) createIntermediateKey(ctx context.Context) (*internal.CryptoKey, error) {
	// Try to get latest from cache.
	sk, err := e.skCache.GetOrLoadLatest(e.partition.SystemKeyID(), func(meta KeyMeta) (*internal.CryptoKey, error) {
		return e.loadLatestOrCreateSystemKey(ctx, meta.ID)
	})

	// fmt.Println("skcreateIntermediateKey", sk, err)
	if err != nil {
		return nil, err
	}

	defer sk.Close()

	ik, err := e.generateKey()
	if err != nil {
		return nil, err
	}

	switch success, err2 := e.tryStoreIntermediateKey(ctx, ik, sk); {
	case success:
		// New key saved successfully, return it.
		return ik, nil
	default:
		// it's no good to us now. throw it away
		ik.Close()

		if err2 != nil {
			return nil, err2
		}
	}

	// If we're here, storing of the newly generated key failed above which means we attempted to
	// save a duplicate key to the metastore. If that's the case, then we know a valid key exists
	// in the metastore, so let's grab it and return it.
	newEkr, err := e.mustLoadLatest(ctx, e.partition.IntermediateKeyID())
	if err != nil {
		return nil, err
	}

	return e.intermediateKeyFromEKR(sk, newEkr)
}

// tryStoreIntermediateKey attempts to persist the encrypted ik to the metastore ignoring all persistence related errors.
// err will be non-nil only if encryption fails.
func (e *envelopeEncryption) tryStoreIntermediateKey(ctx context.Context, ik, sk accessorRevokable) (success bool, err error) {
	encBytes, err := internal.WithKeyFunc(ik, func(keyBytes []byte) ([]byte, error) {
		return internal.WithKeyFunc(sk, func(systemKeyBytes []byte) ([]byte, error) {
			return e.Crypto.Encrypt(keyBytes, systemKeyBytes)
		})
	})
	if err != nil {
		return false, err
	}

	ekr := &EnvelopeKeyRecord{
		ID:           e.partition.IntermediateKeyID(),
		Created:      ik.Created(),
		EncryptedKey: encBytes,
		ParentKeyMeta: &KeyMeta{
			ID:      e.partition.SystemKeyID(),
			Created: sk.Created(),
		},
	}

	return e.tryStore(ctx, ekr), nil
}

// loadLatestOrCreateIntermediateKey gets the most recently created intermediate key for the given id or creates a new one.
func (e *envelopeEncryption) loadLatestOrCreateIntermediateKey(ctx context.Context, id string) (*internal.CryptoKey, error) {
	ikEkr, err := e.Metastore.LoadLatest(ctx, id)
	if err != nil {
		return nil, err
	}

	if ikEkr == nil || e.isEnvelopeInvalid(ikEkr) {
		return e.createIntermediateKey(ctx)
	}
	// fmt.Println("ikEkr", ikEkr.ParentKeyMeta)
	// We've retrieved the latest IK and confirmed its validity. Now let's do the same for its parent key.
	sk, err := e.getOrLoadSystemKey(ctx, *ikEkr.ParentKeyMeta)

	// fmt.Println("sk", sk, err)
	if err != nil {
		return e.createIntermediateKey(ctx)
	}

	defer sk.Close()

	// Only use the loaded IK if it and its parent key is valid.
	if ik := e.getValidIntermediateKey(sk, ikEkr); ik != nil {
		return ik, nil
	}

	// fallback to creating a new one
	return e.createIntermediateKey(ctx)
}

// getOrLoadSystemKey returns a system key from cache if it's already been loaded. Otherwise it retrieves the key
// from the metastore.
func (e *envelopeEncryption) getOrLoadSystemKey(ctx context.Context, meta KeyMeta) (*cachedCryptoKey, error) {
	return e.skCache.GetOrLoad(meta, func(m KeyMeta) (*internal.CryptoKey, error) {
		return e.loadSystemKey(ctx, m)
	})
}

// getValidIntermediateKey returns a new CryptoKey constructed from ekr. It returns nil if sk is invalid or if key initialization fails.
func (e *envelopeEncryption) getValidIntermediateKey(sk accessorRevokable, ekr *EnvelopeKeyRecord) *internal.CryptoKey {
	// IK is only valid if its parent is valid
	if internal.IsKeyInvalid(sk, e.Policy.ExpireKeyAfter) {
		return nil
	}

	ik, err := e.intermediateKeyFromEKR(sk, ekr)
	if err != nil {
		return nil
	}

	// all is well with the loaded IK, use it
	return ik
}

// decryptRow decrypts drr using ik as the parent key and returns the decrypted data.
func decryptRow(ik internal.BytesFuncAccessor, drr DataRowRecord, crypto AEAD) ([]byte, error) {
	return internal.WithKeyFunc(ik, func(bytes []byte) ([]byte, error) {
		// TODO Consider having separate DecryptKey that is functional and handles wiping bytes
		rawDrk, err := crypto.Decrypt(drr.Key.EncryptedKey, bytes)
		if err != nil {
			return nil, err
		}

		defer internal.MemClr(rawDrk)

		return crypto.Decrypt(drr.Data, rawDrk)
	})
}

// EncryptPayload encrypts a provided slice of bytes and returns the data with the data row key and required
// parent information to decrypt the data in the future. It also takes a context used for cancellation.
func (e *envelopeEncryption) EncryptPayload(ctx context.Context, data []byte) (*DataRowRecord, error) {
	defer encryptTimer.UpdateSince(time.Now())
	loader := func(meta KeyMeta) (*internal.CryptoKey, error) {
		log.Debugf("[EncryptPayload] loadLatestOrCreateIntermediateKey: %s", meta.ID)
		return e.loadLatestOrCreateIntermediateKey(ctx, meta.ID)
	}

	// Try to get latest from cache.
	ik, err := e.ikCache.GetOrLoadLatest(e.partition.IntermediateKeyID(), loader)
	if err != nil {
		log.Debugf("[EncryptPayload] GetOrLoadLatest failed: %s", err.Error())
		return nil, err
	}

	defer ik.Close()

	// Note the id doesn't mean anything for DRK. Don't need to truncate created since that is intended
	// to prevent excessive IK/SK creation (we always create new DRK on each write, so not a concern there)
	drk, err := internal.GenerateKey(e.SecretFactory, time.Now().Unix(), AES256KeySize)
	if err != nil {
		log.Debugf("[EncryptPayload] GenerateKey failed: %s", err.Error())
		return nil, err
	}

	defer drk.Close()

	encData, err := internal.WithKeyFunc(drk, func(bytes []byte) ([]byte, error) {
		return e.Crypto.Encrypt(data, bytes)
	})
	if err != nil {
		log.Debugf("[EncryptPayload] WithKeyFunc failed to encrypt data using DRK: %s", err.Error())
		return nil, err
	}

	encBytes, err := internal.WithKeyFunc(ik, func(bytes []byte) ([]byte, error) {
		return internal.WithKeyFunc(drk, func(drkBytes []byte) ([]byte, error) {
			return e.Crypto.Encrypt(drkBytes, bytes)
		})
	})
	if err != nil {
		log.Debugf("[EncryptPayload] WithKeyFunc failed to encrypt DRK using IK: %s", err.Error())
		return nil, err
	}

	return &DataRowRecord{
		Key: &EnvelopeKeyRecord{
			Created:      drk.Created(),
			EncryptedKey: encBytes,
			ParentKeyMeta: &KeyMeta{
				Created: ik.Created(),
				ID:      e.partition.IntermediateKeyID(),
			},
		},
		Data: encData,
	}, nil
}

// DecryptDataRowRecord decrypts a DataRowRecord key and returns the original byte slice provided to the encrypt function.
// It also accepts a context for cancellation.
func (e *envelopeEncryption) DecryptDataRowRecord(ctx context.Context, drr DataRowRecord) ([]byte, error) {
	defer decryptTimer.UpdateSince(time.Now())

	if drr.Key == nil {
		return nil, errors.New("datarow key record cannot be empty")
	}

	if drr.Key.ParentKeyMeta == nil {
		return nil, errors.New("parent key cannot be empty")
	}

	if !e.partition.IsValidIntermediateKeyID(drr.Key.ParentKeyMeta.ID) {
		return nil, errors.New("unable to decrypt record")
	}

	loader := func(meta KeyMeta) (*internal.CryptoKey, error) {
		log.Debugf("[DecryptDataRowRecord] loadIntermediateKey: %s", meta.ID)

		return e.loadIntermediateKey(ctx, meta)
	}

	ik, err := e.ikCache.GetOrLoad(*drr.Key.ParentKeyMeta, loader)
	if err != nil {
		log.Debugf("[DecryptDataRowRecord] GetOrLoad IK failed: %s", err.Error())

		return nil, err
	}

	defer ik.Close()

	return decryptRow(ik, drr, e.Crypto)
}

// loadIntermediateKey fetches a known intermediate key from the metastore and tries to decrypt it using the associated system key.
func (e *envelopeEncryption) loadIntermediateKey(ctx context.Context, meta KeyMeta) (*internal.CryptoKey, error) {
	ekr, err := e.Metastore.Load(ctx, meta.ID, meta.Created)
	if err != nil {
		return nil, err
	}

	if ekr == nil {
		return nil, errors.New("error loading intermediate key from metastore")
	}

	sk, err := e.getOrLoadSystemKey(ctx, *ekr.ParentKeyMeta)
	if err != nil {
		return nil, err
	}

	defer sk.Close()

	return e.intermediateKeyFromEKR(sk, ekr)
}

// Close frees all memory locked by the keys in the session. It should be called
// as soon as its no longer in use.
func (e *envelopeEncryption) Close() error {
	if e.Policy != nil && e.Policy.SharedIntermediateKeyCache {
		return nil
	}

	return e.ikCache.Close()
}

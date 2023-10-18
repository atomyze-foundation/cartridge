package manager

import (
	"crypto/ecdsa"

	"github.com/atomyze-foundation/cartridge/cryptocache"
)

// Manager is responsible for sign/verify operations.
type Manager interface {
	Sign(digest []byte, ecdsaPrivateKey *ecdsa.PrivateKey, ecdsaPublicKey *ecdsa.PublicKey) ([]byte, error)
	Verify(digest, signature []byte, ecdsaPublicKey *ecdsa.PublicKey) error
	SigningIdentity() CartridgeSigningIdentity
	Cache() cryptocache.CryptoCache
}

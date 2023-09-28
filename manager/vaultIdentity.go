package manager

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric/bccsp/utils"
)

// VaultIdentity is an interface that provides access to the identity
type VaultIdentity struct {
	MSPID   string        `protobuf:"bytes,1,opt,name=mspid,proto3" json:"mspid,omitempty"`
	IDBytes []byte        `protobuf:"bytes,2,opt,name=idBytes,proto3" json:"idBytes,omitempty"`
	Manager Manager       `json:"-"`
	Key     *CartridgeKey `json:"-"`
}

// Reset resets struct
func (m *VaultIdentity) Reset() {
	*m = VaultIdentity{}
}

// String converts struct to string reprezentation
func (m *VaultIdentity) String() string {
	return proto.CompactTextString(m)
}

// ProtoMessage indicates the identity is Protobuf serializable
func (m *VaultIdentity) ProtoMessage() {}

// Identifier returns the identifier of that identity
func (m *VaultIdentity) Identifier() *msp.IdentityIdentifier {
	return &msp.IdentityIdentifier{
		ID:    m.MSPID,
		MSPID: m.MSPID,
	}
}

// Verify a signature over some message using this identity as reference
func (m *VaultIdentity) Verify(msg []byte, sig []byte) error {
	hash := sha256.Sum256(msg)
	return m.Manager.Verify(hash[:], sig, m.Key.PubKey)
}

// Serialize converts an identity to bytes
func (m *VaultIdentity) Serialize() ([]byte, error) {
	ident, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return ident, nil
}

// EnrollmentCertificate Returns the underlying ECert representing this user’s identity.
func (m *VaultIdentity) EnrollmentCertificate() []byte {
	return m.IDBytes
}

// VaultSigningIdentity represents singing identity using Manager
type VaultSigningIdentity struct {
	*VaultIdentity
}

// NewVaultSigningIdentity initializes VaultSigningIdentity
func NewVaultSigningIdentity(mspid, certname string, manager Manager) (*VaultSigningIdentity, error) {
	cache := manager.Cache()

	cert, err := cache.GetCrypto(certname)
	if err != nil {
		return nil, fmt.Errorf("failed to find certificate in memory, %w", err)
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("cannot decode cert")
	}
	pubCrt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, ok := pubCrt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid key type, expecting ECDSA Public Key")
	}

	key := &CartridgeKey{PubKey: ecdsaPubKey}

	privatekey, err := cache.GetCrypto(fmt.Sprintf("%s_sk", hex.EncodeToString(key.SKI())))
	if err != nil {
		return nil, fmt.Errorf("failed to find private key in memory, %w", err)
	}

	pkDecoded, err := PEMToPrivateKey(privatekey, nil)
	if err != nil {
		return nil, err
	}

	pkECDSA, ok := pkDecoded.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to assert private key PEM-encoded bytes under interface{} to []byte")
	}

	identity := &VaultSigningIdentity{
		VaultIdentity: &VaultIdentity{
			MSPID:   mspid,
			Manager: manager,
			Key:     &CartridgeKey{PrivKey: pkECDSA, PubKey: ecdsaPubKey},
			IDBytes: cert,
		},
	}

	return identity, nil
}

// Sign the message
func (m *VaultSigningIdentity) Sign(msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	sig, err := m.Manager.Sign(hash[:], m.Key.PrivKey, m.Key.PubKey)
	if err != nil {
		return nil, err
	}

	sigLowS, err := utils.SignatureToLowS(m.Key.PubKey, sig)
	if err != nil {
		return nil, err
	}

	return sigLowS, nil
}

// PublicVersion returns the public parts of this identity
func (m *VaultSigningIdentity) PublicVersion() msp.Identity {
	return m
}

// PrivateKey returns the crypto suite representation of the private key
func (m *VaultSigningIdentity) PrivateKey() core.Key {
	return m.Key
}

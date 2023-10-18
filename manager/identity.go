package manager

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
)

type CartridgeSigningIdentity interface {
	Identifier() *msp.IdentityIdentifier
	Verify(msg []byte, sig []byte) error
	Serialize() ([]byte, error)
	EnrollmentCertificate() []byte
	Sign(msg []byte) ([]byte, error)
	PublicVersion() msp.Identity
	PrivateKey() core.Key
}

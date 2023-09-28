/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cartridge

import (
	"github.com/atomyze-foundation/cartridge/cryptocache"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
)

// ConnectProvider provides all necessary data (endpoints, certs) for connecting to HLF network.
type ConnectProvider interface {
	// IdentityConfig provides user data
	IdentityConfig(cache cryptocache.CryptoCache) (msp.IdentityConfig, error)
	// EndpointConfig provides network data
	EndpointConfig(cache cryptocache.CryptoCache) (fab.EndpointConfig, error)
}

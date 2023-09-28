/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cartridge

import (
	"github.com/atomyze-foundation/cartridge/manager"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/api"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/modlog"
	signingMgr "github.com/hyperledger/fabric-sdk-go/pkg/fab/signingmgr"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/fabpvdr"
)

// ProviderFactory represents the default SDK provider factory.
type ProviderFactory struct {
	manager manager.Manager
}

// NewCartridgeProviderFactory returns the default SDK provider factory.
func NewCartridgeProviderFactory(manager manager.Manager) *ProviderFactory {
	return &ProviderFactory{manager}
}

// CreateCryptoSuiteProvider returns a new default implementation of BCCSP
func (c *ProviderFactory) CreateCryptoSuiteProvider(_ core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	cryptoSuiteProvider := NewCartridgeCryptoSuite(c.manager)
	return cryptoSuiteProvider, nil
}

// CreateSigningManager returns a new default implementation of signing manager
func (c *ProviderFactory) CreateSigningManager(cryptoProvider core.CryptoSuite) (core.SigningManager, error) {
	return signingMgr.New(cryptoProvider)
}

// CreateInfraProvider returns a new default implementation of fabric primitives
func (c *ProviderFactory) CreateInfraProvider(config fab.EndpointConfig) (fab.InfraProvider, error) {
	return fabpvdr.New(config), nil
}

// NewLoggerProvider returns a new default implementation of a logger backend
// This function is separated from the factory to allow logger creation first.
func NewLoggerProvider() api.LoggerProvider {
	return modlog.LoggerProvider()
}

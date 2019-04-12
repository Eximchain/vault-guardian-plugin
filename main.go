package main

import (
	"log"
	"os"

	"github.com/eximchain/vault-guardian-plugin/guardian"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"
)

func main() {
	hclog.Default().Info("HCLOG PLUGIN TEST MAIN")
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:]) // Ignore command, strictly parse flags

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)
	hclog.Default().Info("TLS CONFIG:")
	hclog.Default().Info("CACert:", tlsConfig.CACert)
	hclog.Default().Info("ClientCert:", tlsConfig.ClientCert)
	hclog.Default().Info("ClientKey:", tlsConfig.ClientKey)
	hclog.Default().Info("TLSServerName:", tlsConfig.TLSServerName)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: guardian.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Fatal(err)
	}
}

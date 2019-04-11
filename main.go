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
	log.Println("PLUGIN TEST 1")
	apiClientMeta := &pluginutil.APIClientMeta{}
	log.Println("PLUGIN TEST 2")
	flags := apiClientMeta.FlagSet()
	log.Println("PLUGIN TEST 3")
	flags.Parse(os.Args[1:]) // Ignore command, strictly parse flags
	log.Println("PLUGIN TEST 4")

	tlsConfig := apiClientMeta.GetTLSConfig()
	log.Println("PLUGIN TEST 5")
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)
	log.Println("PLUGIN TEST 6")

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: guardian.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	log.Println("PLUGIN TEST 7")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("PLUGIN TEST 8")
}

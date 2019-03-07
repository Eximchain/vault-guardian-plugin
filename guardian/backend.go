package guardian

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help:         "",
		PathsSpecial: &logical.Paths{Unauthenticated: []string{"login"}},
		Paths: framework.PathAppend([]*framework.Path{
			&framework.Path{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"okta_username": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Username of Okta account to login, probably an email address."},
					"okta_password": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Password for associated Okta account."},
					"get_address": &framework.FieldSchema{
						Type:        framework.TypeBool,
						Description: "Include client's ethereum address on login.  Automatically included for first login.",
						Default:     false,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathLogin,
				},
			},
			&framework.Path{
				Pattern: "authorize",
				Fields: map[string]*framework.FieldSchema{
					"secret_id": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "SecretID of the Guardian AppRole.",
					},
					"okta_url": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Organization's Okta URL.",
					},
					"okta_token": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Permissioned API token from Okta organization.",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.CreateOperation: b.pathAuthorize,
					logical.UpdateOperation: b.pathAuthorize,
				},
			},
			&framework.Path{
				Pattern: "sign",
				Fields: map[string]*framework.FieldSchema{
					"raw_data": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw hashed transaction data to sign, 0x is optional.",
					},
					"address_index": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "Integer index of which generated address to use.",
						Default:     0,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.CreateOperation: b.pathSign,
					logical.UpdateOperation: b.pathSign,
					logical.ReadOperation:   b.pathGetAddress,
				},
			},
			&framework.Path{
				Pattern: "sign-tx",
				Fields: map[string]*framework.FieldSchema{
					"nonce": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "TxParam: nonce is an unsigned 64-bit integer",
					},
					"to": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "TxParam: to should be an address, must begin with 0x.",
					},
					"amount": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "TxParam: if this tx transfers value, amount should be an unsigned 64-bit integer.  Unit is wei.",
						Default:     0,
					},
					"gas_limit": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "TxParam: gas_limit should be an unsigned 64-bit integer",
					},
					"gas_price": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "TxParam: gas_price should be a positive 64-bit integer.",
					},
					"data": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "TxParam: data should either be a hex string (0x optional) or not specified.",
					},
					"chain_id": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "Positive integer chainID for your desired network.",
						Default:     1,
					},
					"address_index": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "Positive integer index of which generated address to use.",
						Default:     0,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.CreateOperation: b.pathSignTx,
					logical.UpdateOperation: b.pathSignTx,
					logical.ReadOperation:   b.pathGetAddress,
				},
			},
		}),
		BackendType: logical.TypeLogical,
	}
	return &b
}

type backend struct {
	*framework.Backend
}

func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	config, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	var result Config
	if config != nil {
		if err := config.DecodeJSON(&result); err != nil {
			return nil, err
		}
	} else {
		result = Config{"", "", ""}
	}
	return &result, nil
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}

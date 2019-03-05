package guardian

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func cleanErrResp(context string, err error) *logical.Response {
	if err == nil {
		return logical.ErrorResponse(context)
	}
	return logical.ErrorResponse(context + "\n\n" + err.Error())
}

func readConfigErrResp(err error) *logical.Response {
	return cleanErrResp("Error reading Config() from Storage: ", err)
}

func makeClientErrResp(err error) *logical.Response {
	return cleanErrResp("Error building Client from Config: ", err)
}

func keyFromTokenErrResp(err error) *logical.Response {
	return cleanErrResp("Failed to load key from token accessor: ", err)
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Fetch login credentials
	oktaUser := data.Get("okta_username").(string)
	oktaPass := data.Get("okta_password").(string)
	getAddress := data.Get("get_address").(bool)

	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return readConfigErrResp(err), err
	}
	client, err := cfg.Client()
	if err != nil {
		return makeClientErrResp(err), err
	}

	// Do we have an account for them?
	newUser, checkErr := client.isNewUser(oktaUser)
	if checkErr != nil {
		return cleanErrResp(fmt.Sprintf("User check failed, here's conf: %#v", cfg), checkErr), checkErr
	}
	pubAddress := ""
	if newUser {
		// Verify it's a real Okta account
		isOktaUser, oktaCheckErr := client.oktaAccountExists(oktaUser)
		if oktaCheckErr != nil {
			return cleanErrResp("Failed to verify whether user's Okta account exists:", oktaCheckErr), oktaCheckErr
		}
		if isOktaUser {
			var createErr error
			pubAddress, createErr = client.createEnduser(oktaUser)
			if createErr != nil {
				return cleanErrResp("Error creating user and keys: ", createErr), createErr
			}
		} else {
			return cleanErrResp("Username does not belong to Guardian's Okta organization, not creating account.", nil), nil
		}
	}

	// Perform the actual login call to verify identity, but don't
	// actually need it client token
	_, loginErr := client.loginEnduser(oktaUser, oktaPass)
	if loginErr != nil {
		return cleanErrResp("Unable to login with Okta with the provided credentials:", loginErr), loginErr
	}

	// This method is prototyped, commenting out while we get core flow working
	singleToken, singleTokenErr := client.makeSingleSignToken(oktaUser)
	if singleTokenErr != nil {
		return cleanErrResp("Error building single-sign token: ", singleTokenErr), singleTokenErr
	}

	var respData map[string]interface{}
	if !newUser && !getAddress {
		respData = map[string]interface{}{"client_token": singleToken}
	} else {
		if getAddress {
			privKeyHex, fetchKeyErr := client.readKeyHexByUsername(oktaUser)
			if fetchKeyErr != nil {
				return cleanErrResp("Error fetching your key: ", fetchKeyErr), fetchKeyErr
			}
			var buildAddressErr error
			pubAddress, buildAddressErr = AddressFromHexKey(privKeyHex)
			if buildAddressErr != nil {
				return cleanErrResp("Error building address from the private key: ", buildAddressErr), buildAddressErr
			}
		}
		respData = map[string]interface{}{
			"client_token": singleToken,
			"address":      pubAddress,
		}
	}
	return &logical.Response{Data: respData}, nil
}

func (b *backend) pathAuthorize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID, ok := data.GetOk("secret_id")
	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	if loadCfgErr != nil {
		return readConfigErrResp(loadCfgErr), loadCfgErr
	}
	if ok {
		client, makeClientErr := cfg.Client()
		if makeClientErr != nil {
			return makeClientErrResp(makeClientErr), makeClientErr
		}
		guardianToken, tokenErr := client.tokenFromSecretID(secretID.(string))
		if tokenErr != nil {
			return logical.ErrorResponse("Error fetching token using SecretID: " + tokenErr.Error()), tokenErr
		}
		cfg.GuardianToken = guardianToken
	}
	if cfg.GuardianToken == "" {
		return logical.ErrorResponse("secret_id was missing, could not get a guardianToken"), nil
	}

	oktaURL, ok := data.GetOk("okta_url")
	if ok {
		cfg.OktaURL = oktaURL.(string)
	}
	if cfg.OktaURL == "" {
		return logical.ErrorResponse("Must provide an okta_url"), nil
	}

	oktaToken, ok := data.GetOk("okta_token")
	if ok {
		cfg.OktaToken = oktaToken.(string)
	}
	if cfg.OktaToken == "" {
		return logical.ErrorResponse("Must provide an okta_token"), nil
	}

	jsonCfg, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return logical.ErrorResponse("Error making a StorageEntryJSON out of the config: " + err.Error()), err
	}
	if err := req.Storage.Put(ctx, jsonCfg); err != nil {
		return logical.ErrorResponse("Error saving the config StorageEntry: " + err.Error()), err
	}

	return &logical.Response{
		Data: map[string]interface{}{"configUpdated": true},
	}, nil
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawDataStr := data.Get("raw_data")

	rawDataBytes, decodeErr := hex.DecodeString(rawDataStr.(string))
	if decodeErr != nil {
		return logical.ErrorResponse("Unable to decode raw_data string from hex to bytes: " + decodeErr.Error()), decodeErr
	}

	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	if loadCfgErr != nil {
		return readConfigErrResp(loadCfgErr), loadCfgErr
	}
	client, makeClientErr := cfg.Client()
	if makeClientErr != nil {
		return makeClientErrResp(makeClientErr), makeClientErr
	}

	privKeyHex, readKeyErr := client.readKeyHexByTokenAccessor(req.ClientTokenAccessor)
	if readKeyErr != nil {
		return keyFromTokenErrResp(readKeyErr), readKeyErr
	}
	sigBytes, err := SignWithHexKey(rawDataBytes, privKeyHex)
	if err != nil {
		return logical.ErrorResponse("Failed to unmarshall key & sign: " + err.Error()), err
	}
	sigHex := hex.EncodeToString(sigBytes)
	freshToken, freshTokenErr := client.makeFreshToken(req.ClientTokenAccessor)
	if freshTokenErr != nil {
		return cleanErrResp("Unable to create a fresh_client_token after signing: ", freshTokenErr), freshTokenErr
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature":          "0x" + sigHex,
			"fresh_client_token": freshToken,
		},
	}, nil
}

func (b *backend) pathGetAddress(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	if loadCfgErr != nil {
		return readConfigErrResp(loadCfgErr), loadCfgErr
	}
	client, makeClientErr := cfg.Client()
	if makeClientErr != nil {
		return makeClientErrResp(makeClientErr), makeClientErr
	}
	privKeyHex, readKeyErr := client.readKeyHexByTokenAccessor(req.ClientTokenAccessor)
	if readKeyErr != nil {
		return keyFromTokenErrResp(readKeyErr), readKeyErr
	}
	pubAddress, getAddressErr := AddressFromHexKey(privKeyHex)
	if getAddressErr != nil {
		return logical.ErrorResponse("Fail to derive address from private key: " + getAddressErr.Error()), getAddressErr
	}
	return &logical.Response{
		Data: map[string]interface{}{"public_address": pubAddress},
	}, nil
}

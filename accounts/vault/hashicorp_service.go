package vault

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/vault/envvars"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
	"strings"
	"sync"
)

type hashicorpService struct {
	clientFactory func() (clientI, error)
	clientConfig ClientConfig
	secrets []Secret
	stateLock sync.RWMutex
	client clientI
	secretsByAccount map[accounts.Account]Secret
}

func NewHashicorpService(clientConfig ClientConfig, secrets []Secret) VaultService {
	return &hashicorpService{
		clientFactory: createDefaultClient,
		clientConfig: clientConfig,
		secrets: secrets,
	}
}

func createDefaultClient() (clientI, error) {
	conf := api.DefaultConfig()
	client, err := api.NewClient(conf)

	if err != nil {
		return nil, err
	}

	return clientDelegate{client}, nil
}

const (
	walletClosed = "Closed"
	vaultUninitialised = "Vault uninitialised"
	vaultSealed = "Vault sealed"
	healthcheckFailed = "Vault healthcheck failed"
	walletOpen = "Open, vault initialised and unsealed"
)

func (s *hashicorpService) Status() (string, error) {
	if s.client == nil {
		return walletClosed, nil
	}

	health, err := s.client.Sys().Health()

	if err != nil {
		return healthcheckFailed, err
	}

	if !health.Initialized {
		return vaultUninitialised, errors.New(vaultUninitialised)
	}

	if health.Sealed {
		return vaultSealed, errors.New(vaultSealed)
	}

	return walletOpen, nil
}

func (s *hashicorpService) IsOpen() bool {
	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

	return s.client != nil
}

func (s *hashicorpService) Open() error {
	s.stateLock.Lock() // State lock is enough since there's no connection yet at this point
	defer s.stateLock.Unlock()

	// If the environment variable `VAULT_TOKEN` is present, the token will be automatically added to the created client

	var err error
	s.client, err = s.clientFactory()

	if err != nil {
		return err
	}

	if err := s.client.SetAddress(s.clientConfig.Url); err != nil {
		return err
	}

	// If the roleID and secretID environment variables are present, these will be used to authenticate the client and replace the default VAULT_TOKEN value
	// As using Approle is preferred over using the standalone token, an error will be returned if only one of these environment variables is set
	roleId, rIdOk := os.LookupEnv(envvars.VaultRoleId)
	secretId, sIdOk := os.LookupEnv(envvars.VaultSecretId)

	if rIdOk != sIdOk {
		return fmt.Errorf("both %q and %q environment variables must be set to use Approle authentication", envvars.VaultRoleId, envvars.VaultSecretId)
	}

	if rIdOk && sIdOk {
		authData := map[string]interface{} {"role_id": roleId, "secret_id": secretId}

		if s.clientConfig.Approle == "" {
			s.clientConfig.Approle = "approle"
		}

		authResponse, err := s.client.Logical().Write(fmt.Sprintf("auth/%s/login", s.clientConfig.Approle), authData)

		if err != nil {
			return err
		}

		token := authResponse.Auth.ClientToken
		s.client.SetToken(token)
	}

	return nil
}

func (s *hashicorpService) Close() error {
	if !s.IsOpen() {
		return nil
	}

	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	s.client.ClearToken()
	s.client = nil
	s.secretsByAccount = nil

	return nil
}

func (s *hashicorpService) getAccounts() ([]accounts.Account, error) {
	if status, err := s.Status(); status == walletClosed {
		return nil, errors.New("Wallet closed")
	} else if err != nil {
		return nil, err
	}

	secretsByAccount := make(map[accounts.Account]Secret)

	for i, secret := range s.secrets {
		acct, err := s.getAccount(secret)

		if err != nil {
			return nil, err
		}

		secretsByAccount[acct] = secret
	}

	s.stateLock.Lock()
	s.secretsByAccount = secretsByAccount
	s.stateLock.Unlock()
	
	accts := make([]accounts.Account, len(secretsByAccount))
	
	i := 0
	for a := range secretsByAccount { 
		accts[i] = a
		i++
	}

	return accts, nil
}

func (s *hashicorpService) getAccount(secret Secret) (accounts.Account, error) {
	path, queryParams, err := secret.toRequestData()

	if err != nil {
		return accounts.Account{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	s.stateLock.RLock()
	vaultResponse, err := s.client.Logical().ReadWithData(path, queryParams)
	s.stateLock.RUnlock()

	if err != nil {
		return accounts.Account{}, errors.WithMessage(err, "unable to retrieve secret from vault")
	}

	data := vaultResponse.Data["data"]

	m := data.(map[string]interface{})
	acct, ok := m[secret.AccountID]

	if !ok {
		return accounts.Account{}, errors.WithMessage(err, "no value found in vault with provided AccountID")
	}

	strAcct, ok := acct.(string)

	if !ok {
		return accounts.Account{}, errors.WithMessage(err, "AccountID value in vault is not plain string")
	}

	if !common.IsHexAddress(strAcct) {
		return accounts.Account{}, errors.WithMessage(err, "unable to get account from vault")
	}

	u := fmt.Sprintf("%v/v1/%v?version=%v", s.clientConfig.Url, path, secret.Version)
	url, err := parseURL(u)

	if err != nil {
		return accounts.Account{}, errors.WithMessage(err, "unable to create account URL")
	}

	return accounts.Account{Address: common.HexToAddress(strAcct), URL: url}, nil
}

func (s *hashicorpService) GetPrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	
	secret := s.secretsByAccount[account]
	
	path, queryParams, err := secret.toRequestData()

	if err != nil {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	s.stateLock.RLock()
	vaultResponse, err := s.client.Logical().ReadWithData(path, queryParams)
	s.stateLock.RUnlock()

	if err != nil {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "unable to retrieve secret from vault")
	}

	data := vaultResponse.Data["data"]

	m := data.(map[string]interface{})
	k, ok := m[secret.KeyID]

	if !ok {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "no value found in vault with provided KeyID")
	}

	strK, ok := k.(string)

	if !ok {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "KeyID value in vault is not plain string")
	}

	key, err := crypto.HexToECDSA(strK)


	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	return key, nil
}

func (s *hashicorpService) Store(key *ecdsa.PrivateKey) (common.Address, error) {
	address := crypto.PubkeyToAddress(key.PublicKey)
	addrHex := address.Hex()

	if strings.HasPrefix(addrHex, "0x") {
		addrHex = strings.Replace(addrHex, "0x", "", 1)
	}

	keyBytes := crypto.FromECDSA(key)
	keyHex := hex.EncodeToString(keyBytes)

	secret := s .secrets[0]

	path := fmt.Sprintf("%s/data/%s", secret.SecretEngine, secret.Name)

	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		secret.AccountID: addrHex,
		secret.KeyID:     keyHex,
	}

	if _, err := s.client.Logical().Write(path, data); err != nil {
		return common.Address{}, errors.WithMessage(err, "unable to write secret to vault")
	}

	return address, nil
}

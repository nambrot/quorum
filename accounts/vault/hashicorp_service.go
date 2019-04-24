package vault

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
	"sort"
	"strings"
	"sync"
)

// hashicorpService is a vaultService and defines the functionality required to read/write to a Hashicorp Vault
type hashicorpService struct {
	clientFactory        clientDelegateFactory
	secrets              []HashicorpSecret
	stateLock            sync.RWMutex
	clientConfig         HashicorpClientConfig
	client               clientDelegate
	acctSecretsByAddress map[common.Address][]acctAndSecret // The same address may be provided in more than one way (e.g. by specifying v0 and a specific version which happens to be the latest version).  As a result multiple secrets may be defined for the same address
}

// clientDelegateFactory defines a factory function to create a delegate for the client of the Hashicorp Vault api.  This has been defined to enable mocking of the client in testing.
//
// The defaultClientDelegateFactory should be used in most situations except where mocking of the client is required.  In this case, define a custom clientDelegateFactory to return a custom implementation of clientDelegate.
type clientDelegateFactory func() (clientDelegate, error)

// defaultClientDelegateFactory creates a clientDelegate using the default Hashicorp api configuration
func defaultClientDelegateFactory() (clientDelegate, error) {
	conf := api.DefaultConfig()
	client, err := api.NewClient(conf)

	if err != nil {
		return nil, err
	}

	return defaultClientDelegate{client}, nil
}

// clientDelegate is used to expose and act as a delegate for the methods of the Hashicorp Vault client api required by a the hashicorpService.  This is to enable mocking of the client when testing.
//
// defaultClientDelegate should be used in most situations except where mocking of the client is required.
type clientDelegate interface {
	Logical() logicalDelegate
	Sys() sysDelegate
	SetAddress(addr string) error
	SetToken(v string)
	ClearToken()
}

// logicalDelegate is used to expose and act as a delegate for the methods of the Hashicorp Vault logical api required by the hashicorpService.  This is to enable mocking of the logical type when testing.
type logicalDelegate interface{
	ReadWithData(path string, data map[string][]string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

// sysDelegate is used to expose and act as a delegate for the methods of the Hashicorp Vault sys api required by the hashicorpService.  This is to enable mocking of the sys type when testing.
type sysDelegate interface{
	Health() (*api.HealthResponse, error)
}

// defaultClientDelegate is a clientDelegate which embeds the Hashicorp Vault client api.  Other than Logical() and Sys() (which also return delegates), the methods exposed by the clientDelegate interface behave in exactly the same way as the Vault client api type.
type defaultClientDelegate struct {
	*api.Client
}

// Logical implements vault.clientDelegate returning the Hashicorp Vault api Logical type as a logicalDelegate
func (cd defaultClientDelegate) Logical() logicalDelegate {
	return cd.Client.Logical()
}

// Sys implements vault.clientDelegate returning the Hashicorp Vault api Sys type as a sysDelegate
func (cd defaultClientDelegate) Sys() sysDelegate {
	return cd.Client.Sys()
}

// acctAndSecret stores a HashicorpSecret with its corresponding accounts.Account once retrieved from the Vault
type acctAndSecret struct {
	acct accounts.Account
	secret HashicorpSecret
}

//TODO duplicated code from account_cache.go

// accountsByUrl implements the sort interface to enable the sorting of a slice of accounts by their urls
type accountsByUrl []accounts.Account

func (a accountsByUrl) Len() int {
	return len(a)
}

func (a accountsByUrl) Less(i, j int) bool {
	return (a[i].URL).Cmp(a[j].URL) < 0
}

func (a accountsByUrl) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// newHashicorpService is the hashicorpService constructor.  The default clientFactory is defined (i.e. the default configuration as defined by the Hashicorp Vault client api)
func newHashicorpService(clientConfig HashicorpClientConfig, secrets []HashicorpSecret) vaultService {
	return &hashicorpService{
		clientFactory: defaultClientDelegateFactory,
		clientConfig:  clientConfig,
		secrets:       secrets,
	}
}

// A Hashicorp Vault status
const (
	walletClosed = "Closed"
	vaultUninitialised = "Vault uninitialised"
	vaultSealed = "Vault sealed"
	healthcheckFailed = "Vault healthcheck failed"
	walletOpen = "Open, vault initialised and unsealed"
)

// Status implements vault.vaultService using the Hashicorp Vault health api to return a status message for the vault
func (s *hashicorpService) Status() (string, error) {
	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

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

// IsOpen implements vault.vaultService and returns true if the vault client has been created
func (s *hashicorpService) IsOpen() bool {
	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

	return s.client != nil
}

// Environment variable to be to AppRole authentication credentials
const (
	VaultRoleId   = "VAULT_ROLE_ID"
	VaultSecretId = "VAULT_SECRET_ID"
)


var (
	// cannotAuthenticateErr is returned when the necessary environment variables have not been defined in order to authenticate to the Vault
	cannotAuthenticateErr = fmt.Errorf("Unable to authenticate client.  Set the %v and %v env vars to use AppRole authentication.  Set %v env var to use Token authentication", VaultRoleId, VaultSecretId, api.EnvVaultToken)

	// approleAuthenticationErr is returned when only one of the AppRole credential environment variables has been set.  Both are required in order to authenticate with the Vault using the AppRole auth method.
	approleAuthenticationErr = fmt.Errorf("both %v and %v environment variables must be set to use Approle authentication", VaultRoleId, VaultSecretId)

	// cannotAuthenticatePrefixErr is returned when an environment variable prefix has been defined for the vault client but the environment variables using that prefix, necessary to authenticate to the vault, have not been defined
	cannotAuthenticatePrefixErr = fmt.Errorf("Unable to authenticate client.  Env var prefix provided in Vault client config but prefixed env vars not set.  Set the <PREFIX>_%v and <PREFIX>_%v env vars to use AppRole authentication.  Set <PREFIX>_%v env var to use Token authentication", VaultRoleId, VaultSecretId, api.EnvVaultToken)

	// approleAuthenticationPrefixErr is returned when an environment variable prefix has been defined for the vault client but only one of the prefixed AppRole credential environment variables has been set.  Both are required in order to authenticate with the Vault using the AppRole auth method.
	approleAuthenticationPrefixErr = fmt.Errorf("both <PREFIX>_%v and <PREFIX>_%v environment variables must be set to use Approle authentication", VaultRoleId, VaultSecretId)
)

// Open implements vault.vaultService to create a Hashicorp Vault client and authenticate that client to the Vault defined in the client config.  Authentication credentials are retrieved from environment variables.  The environment variables are checked as follows.
//
// If an environment variable prefix is defined for the client then:
//
// 1. Use prefixed approle env vars to authenticate, else
//
// 2. Use prefixed token env var to authenticate, else
//
// 3. Return error
//
// If an environment variable prefix is not defined for the client then:
//
// 1. Use global approle env vars to authenticate, else
//
// 2. Use global token env var to authenticate, else
//
// 3. Return error
//
// If an error is encountered during the AppRole authentication this will be returned.  If an incorrect token is provided, this will not be detected until a request is made to read/write to the vault.
func (s *hashicorpService) Open() error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	client, err := s.clientFactory()

	if err != nil {
		return err
	}

	if err := client.SetAddress(s.clientConfig.Url); err != nil {
		return err
	}

	s.client = client


	prefix := s.clientConfig.EnvVarPrefix

	if prefix != "" {
		roleId, rIdOk := os.LookupEnv(prefix + "_" + VaultRoleId)
		secretId, sIdOk := os.LookupEnv(prefix + "_" + VaultSecretId)
		token, tOk := os.LookupEnv(prefix + "_" + api.EnvVaultToken)

		if !(rIdOk || sIdOk || tOk) {
			return cannotAuthenticatePrefixErr
		}

		if rIdOk != sIdOk {
			return approleAuthenticationPrefixErr
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
		} else {
			s.client.SetToken(token)
		}

		return nil
	}

	roleId, rIdOk := os.LookupEnv(VaultRoleId)
	secretId, sIdOk := os.LookupEnv(VaultSecretId)
	token, tOk := os.LookupEnv(api.EnvVaultToken)

	if !(rIdOk || sIdOk || tOk) {
		return cannotAuthenticateErr
	}

	if rIdOk != sIdOk {
		return approleAuthenticationErr
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
	} else {
		s.client.SetToken(token)
	}

	return nil
}

// Close implements vault.vaultService to clear the state of the service by removing the client, client token and stored accounts
func (s *hashicorpService) Close() error {
	if !s.IsOpen() {
		return nil
	}

	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	s.client.ClearToken()
	s.client = nil
	s.acctSecretsByAddress = nil

	return nil
}

// GetAccounts implements vault.vaultService to retrieve the corresponding accounts for the HashicorpSecrets managed by the service.  If an account cannot be retrieved for a particular secret, the error is stored to be returned later and retrieval is attempted for the remaining secrets.
//
// The account address is retrieved directly from the vault.  The account url is determined from the secret config.  The returned account slice will be sorted alphabetically by url.
func (s *hashicorpService) GetAccounts() ([]accounts.Account, []error) {
	if status, err := s.Status(); status == walletClosed {
		return nil, []error{errors.New("Wallet closed")}
	} else if err != nil {
		return nil, []error{err}
	}

	acctSecretsByAddress := make(map[common.Address][]acctAndSecret)
	var accts []accounts.Account

	var errs []error

	s.stateLock.RLock()
	secrets := s.secrets
	s.stateLock.RUnlock()

	for _, secret := range secrets {
		url, err := s.getAccountUrl(secret)

		if err != nil {
			errs = append(errs, errors.WithMessage(err, fmt.Sprintf("error getting account url for %+v", secret)))
			continue
		}

		addr, err := s.getAddress(secret)

		if err != nil {
			errs = append(errs, errors.WithMessage(err, fmt.Sprintf("error getting address for account %v", url)))
			continue
		}

		acctSecret := acctAndSecret{acct: accounts.Account{Address: addr, URL: url}, secret: secret}

		acctSecretsByAddress[addr] = append(acctSecretsByAddress[addr], acctSecret)
		accts = append(accts, accounts.Account{Address: addr, URL: url})
	}

	s.stateLock.Lock()
	s.acctSecretsByAddress = acctSecretsByAddress
	s.stateLock.Unlock()

	sort.Sort(accountsByUrl(accts))

	return accts, errs
}

// getAccountUrl creates the url for a particular HashicorpSecret, including the secret name, secret engine name, and version.  This url can be used to with the Hashicorp Vault HTTP api to retrieve the secret values.
func (s *hashicorpService) getAccountUrl(secret HashicorpSecret) (accounts.URL, error) {
	path, _, err := secret.toRequestData()

	if err != nil {
		return accounts.URL{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

	u := fmt.Sprintf("%v/v1/%v?version=%v", s.clientConfig.Url, path, secret.Version)
	url, err := parseURL(u)

	if err != nil {
		return accounts.URL{}, errors.WithMessage(err, "unable to create account URL")
	}

	return url, nil
}

// getAddress retrieves the common.Address for a HashicorpSecret from the Vault.  The hex representation of the address is retrieved from the Vault and converted to the common.Address type.
func (s *hashicorpService) getAddress(secret HashicorpSecret) (common.Address, error) {
	path, queryParams, err := secret.toRequestData()

	if err != nil {
		return common.Address{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	s.stateLock.RLock()
	//TODO reliably zero this response and all values extracted from it once account has been retrieved
	vaultResponse, err := s.client.Logical().ReadWithData(path, queryParams)
	s.stateLock.RUnlock()

	if err != nil {
		return common.Address{}, errors.WithMessage(err, "unable to retrieve secret from vault")
	}

	data := vaultResponse.Data["data"]

	m := data.(map[string]interface{})
	acct, ok := m[secret.AccountID]

	if !ok {
		return common.Address{}, fmt.Errorf("no value found in vault with provided AccountID %v", secret.AccountID)
	}

	strAcct, ok := acct.(string)

	if !ok {
		return common.Address{}, errors.New("AccountID value in vault is not plain string")
	}

	if !common.IsHexAddress(strAcct) {
		return common.Address{}, errors.New("value in vault is not a valid hex-encoded Ethereum address")
	}

	return common.HexToAddress(strAcct), nil
}

// GetPrivateKey implements vault.vaultService to retrieve the private key for a particular account from the Vault.
//
// Where possible the bytes of the key should be zeroed after use to prevent private data persisting in memory
func (s *hashicorpService) GetPrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

	acctAndSecrets, ok := s.acctSecretsByAddress[account.Address]

	if !ok {
		return &ecdsa.PrivateKey{}, accounts.ErrUnknownAccount
	}

	// if the provided account has an empty url then take the first secret found for this account address, else search for the secret corresponding to an account that has the same url
	var secret HashicorpSecret
	for _, as := range acctAndSecrets {
		if account.URL == (accounts.URL{}) || account.URL == as.acct.URL {
			secret = as.secret
			break
		}
	}

	if secret == (HashicorpSecret{}) {
		return &ecdsa.PrivateKey{}, accounts.ErrUnknownAccount
	}

	path, queryParams, err := secret.toRequestData()

	if err != nil {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	vaultResponse, err := s.client.Logical().ReadWithData(path, queryParams)

	if err != nil {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "unable to retrieve secret from vault")
	}

	data, ok := vaultResponse.Data["data"]
	if !ok {
		return &ecdsa.PrivateKey{}, errors.New("vault response does not contain 'data' field")
	}

	m := data.(map[string]interface{})
	k, ok := m[secret.KeyID]

	if !ok {
		return &ecdsa.PrivateKey{}, fmt.Errorf("no value found in vault with provided KeyID %v", secret.KeyID)
	}

	strK, ok := k.(string)

	if !ok {
		return &ecdsa.PrivateKey{}, errors.New("KeyID value in vault is not plain string")
	}

	key, err := crypto.HexToECDSA(strK)

	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	return key, nil
}

// Store implements vault.vaultService to store the provided private key in the vault.  The key is stored in the first secret in the service's HashicorpSecret slice.  The values stored in the vault are the hex representation of the account address (derived from the private key) and the hex representation of the private key
func (s *hashicorpService) Store(key *ecdsa.PrivateKey) (common.Address, error) {
	address := crypto.PubkeyToAddress(key.PublicKey)
	addrHex := address.Hex()

	if strings.HasPrefix(addrHex, "0x") {
		addrHex = strings.Replace(addrHex, "0x", "", 1)
	}

	keyBytes := crypto.FromECDSA(key)
	keyHex := hex.EncodeToString(keyBytes)

	s.stateLock.RLock()
	defer s.stateLock.RUnlock()
	secret := s.secrets[0]

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

package vault

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/vault/envvars"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
	"reflect"
	"sort"
	"testing"
)

type mockClientDelegate struct {
	logicalMock func() logicalDelegate
	sysMock func() sysDelegate
	setAddressMock func(addr string) error
	setTokenMock func(v string)
	clearTokenMock func()
}

func (m mockClientDelegate) Logical() logicalDelegate {
	return m.logicalMock()
}

func (m mockClientDelegate) Sys() sysDelegate {
	return m.sysMock()
}

func (m mockClientDelegate) SetAddress(addr string) error {
	return m.setAddressMock(addr)
}

func (m mockClientDelegate) SetToken(v string) {
	m.setTokenMock(v)
}

func (m mockClientDelegate) ClearToken() {
	m.clearTokenMock()
}

type mockSysDelegate struct {
	healthMock func() (*api.HealthResponse, error)
}

func (m mockSysDelegate) Health() (*api.HealthResponse, error) {
	return m.healthMock()
}

type mockLogicalDelegate struct {
	readWithDataMock func(path string, data map[string][]string) (*api.Secret, error)
	writeMock func(path string, data map[string]interface{}) (*api.Secret, error)
}

func (m mockLogicalDelegate) ReadWithData(path string, data map[string][]string) (*api.Secret, error) {
	return m.readWithDataMock(path, data)
}

func (m mockLogicalDelegate) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	return m.writeMock(path, data)
}

func TestAccountsByUrl(t *testing.T) {
	a1 := accounts.Account{URL: accounts.URL{Scheme: "http", Path: "localhost:8080"}}
	a2 := accounts.Account{URL: accounts.URL{Scheme: "http", Path: "localhost:9080"}}
	a3 := accounts.Account{URL: accounts.URL{Scheme: "http", Path: "anotherhost:8080"}}

	toSort := accountsByUrl{
		a1, a2, a3,
	}

	wantLen := 3
	if toSort.Len() != wantLen {
		t.Errorf("accountsByUrl Len() error, want %v got %v", wantLen, toSort.Len())
	}

	want := accountsByUrl{
		a3, a1, a2,
	}

	sort.Sort(toSort)

	if !reflect.DeepEqual(toSort, want) {
		t.Errorf("accountsByUrl sort error\nwant: %v\ngot : %v", want, toSort)
	}
}

func TestStatusWalletClosedIfNilClient(t *testing.T) {
	s := hashicorpService{}

	status, err := s.status()

	if status != walletClosed && err != nil {
		t.Errorf("unexpected results\nwant: %v, %v\ngot : %v, %v", walletClosed, nil, status, err)
	}
}

func TestStatusReturnsErrorIfUnableToPerformHealthcheck(t *testing.T) {
	e := errors.New("some error")

	mockSys := mockSysDelegate{
		healthMock: func() (*api.HealthResponse, error) {
			return &api.HealthResponse{}, e
		},
	}

	mockClient := mockClientDelegate{
		sysMock: func() sysDelegate {
			return mockSys
		},
	}

	s := hashicorpService{client: mockClient}

	status, err := s.status()

	if status != healthcheckFailed && err != e {
		t.Errorf("unexpected results\nwant: %v, %v\ngot : %v, %v", healthcheckFailed, e, status, err)
	}
}

func TestStatusVaultUninitialised(t *testing.T) {
	mockSys := mockSysDelegate{
		healthMock: func() (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: false}, nil
		},
	}

	mockClient := mockClientDelegate{
		sysMock: func() sysDelegate {
			return mockSys
		},
	}

	s := hashicorpService{client: mockClient}

	status, err := s.status()

	wantErr := errors.New(vaultUninitialised)

	if status != vaultUninitialised && err != wantErr {
		t.Errorf("unexpected results\nwant: %v, %v\ngot : %v, %v", vaultUninitialised, wantErr, status, err)
	}
}

func TestStatusVaultSealed(t *testing.T) {
	mockSys := mockSysDelegate{
		healthMock: func() (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: true, Sealed: true}, nil
		},
	}

	mockClient := mockClientDelegate{
		sysMock: func() sysDelegate {
			return mockSys
		},
	}

	s := hashicorpService{client: mockClient}

	status, err := s.status()

	wantErr := errors.New(vaultSealed)

	if status != vaultSealed && err != wantErr {
		t.Errorf("unexpected results\nwant: %v, %v\ngot : %v, %v", vaultSealed, wantErr, status, err)
	}
}

func TestStatusWalletOpen(t *testing.T) {
	mockSys := mockSysDelegate{
		healthMock: func() (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: true, Sealed: false}, nil
		},
	}

	mockClient := mockClientDelegate{
		sysMock: func() sysDelegate {
			return mockSys
		},
	}

	s := hashicorpService{client: mockClient}

	status, err := s.status()

	if status != walletOpen && err != nil {
		t.Errorf("unexpected results\nwant: %v, %v\ngot : %v, %v", walletOpen, nil, status, err)
	}
}

func TestIsOpenTrueIfClientNonNil(t *testing.T) {
	s := hashicorpService{client: mockClientDelegate{}}

	if b := s.isOpen(); !b {
		t.Errorf("unexpected result: want %v, got %v", true, b)
	}
}

func TestIsOpenFalseIfClientNil(t *testing.T) {
	s := hashicorpService{}

	if b := s.isOpen(); b {
		t.Errorf("unexpected result: want %v, got %v", false, b)
	}
}

func TestOpenErrorCreatingClientReturnsError(t *testing.T) {
	e := errors.New("an error")

	var mockClientDelegateFactory clientDelegateFactory
	mockClientDelegateFactory = func() (clientDelegate, error) {
		return mockClientDelegate{}, e
	}

	s := hashicorpService{
		clientFactory: mockClientDelegateFactory,
	}

	err := s.open()

	if err != e {
		t.Errorf("want: %v\ngot : %v", e, err)
	}
}

func TestOpenErrorConfiguringClientReturnsError(t *testing.T) {
	e := errors.New("an error")

	mockClientDelegate := mockClientDelegate{
		setAddressMock: func(addr string) error {
			return e
		},
	}

	var mockClientDelegateFactory clientDelegateFactory
	mockClientDelegateFactory = func() (clientDelegate, error) {
		return mockClientDelegate, nil
	}

	s := hashicorpService{
		clientFactory: mockClientDelegateFactory,
	}

	err := s.open()

	if err != e {
		t.Errorf("want: %v\ngot : %v", e, err)
	}
}

func TestOpenWithNoEnvVarsSetReturnsError(t *testing.T) {
	unsetEnvVars(t)

	mockClientDelegate := mockClientDelegate{
		setAddressMock: func(addr string) error {
			return nil
		},
	}

	var mockClientDelegateFactory clientDelegateFactory
	mockClientDelegateFactory = func() (clientDelegate, error) {
		return mockClientDelegate, nil
	}

	s := hashicorpService{
		clientFactory: mockClientDelegateFactory,
	}

	err := s.open()

	if err != cannotAuthenticateErr {
		t.Errorf("want: %v\ngot : %v", cannotAuthenticateErr, err)
	}
}

func TestOpenOnlyRoleIdEnvVarSetReturnsError(t *testing.T) {
	unsetEnvVars(t)
	defer unsetEnvVars(t)
	err := os.Setenv(envvars.VaultRoleId, "some value")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	mockClientDelegate := mockClientDelegate{
		setAddressMock: func(addr string) error {
			return nil
		},
	}

	var mockClientDelegateFactory clientDelegateFactory
	mockClientDelegateFactory = func() (clientDelegate, error) {
		return mockClientDelegate, nil
	}

	s := hashicorpService{
		clientFactory: mockClientDelegateFactory,
	}

	err = s.open()

	if err != approleAuthenticationErr {
		t.Errorf("want: %v\ngot : %v", approleAuthenticationErr, err)
	}
}

func TestOpenOnlySecretIdEnvVarSetReturnsError(t *testing.T) {
	unsetEnvVars(t)
	defer unsetEnvVars(t)
	err := os.Setenv(envvars.VaultSecretId, "some value")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	mockClientDelegate := mockClientDelegate{
		setAddressMock: func(addr string) error {
			return nil
		},
	}

	var mockClientDelegateFactory clientDelegateFactory
	mockClientDelegateFactory = func() (clientDelegate, error) {
		return mockClientDelegate, nil
	}

	s := hashicorpService{
		clientFactory: mockClientDelegateFactory,
	}

	err = s.open()

	if err != approleAuthenticationErr {
		t.Errorf("want: %v\ngot : %v", approleAuthenticationErr, err)
	}
}

var approleTests = []struct {
	name, configuredPath, usedPath string
}{
	{ name: "no approle path configured then default used", configuredPath: "", usedPath: "approle" },
	{ name: "approle path configured then is used", configuredPath: "customapprolepath", usedPath: "customapprolepath" },
}
func TestOpenApproleEnvVarsCreatesAuthenticatedClient(t *testing.T) {
	for _, test := range approleTests {
		t.Run(test.name, func(t *testing.T) {
			unsetEnvVars(t)
			defer unsetEnvVars(t)
			roleId := "a role id"
			err := os.Setenv(envvars.VaultRoleId, roleId)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			secretId := "a secret id"
			err = os.Setenv(envvars.VaultSecretId, secretId)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			token := "sometoken"
			authResponse := api.Secret{Auth: &api.SecretAuth{ClientToken: token}}

			// capture the writeMock() method's args by storing them in these variables
			var writePathArg string
			var writeDataArg map[string]interface{}
			mockLogicalDelegate := mockLogicalDelegate{
				writeMock: func(path string, data map[string]interface{}) (*api.Secret, error) {
					writePathArg = path
					writeDataArg = data
					return &authResponse, nil
				},
			}

			// capture the SetToken() method's arg by storing it in this variable
			var setTokenArg string
			mockClientDelegate := mockClientDelegate{
				setAddressMock: func(addr string) error {
					return nil
				},
				logicalMock: func() logicalDelegate {
					return mockLogicalDelegate
				},
				setTokenMock: func(v string) {
					setTokenArg = v
				},
			}

			var mockClientDelegateFactory clientDelegateFactory
			mockClientDelegateFactory = func() (clientDelegate, error) {
				return mockClientDelegate, nil
			}

			s := hashicorpService{
				clientFactory: mockClientDelegateFactory,
				clientConfig: HashicorpClientConfig{Approle: test.configuredPath},
			}

			err = s.open()

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			wantPath := fmt.Sprintf("auth/%v/login", test.usedPath)
			if writePathArg !=  wantPath {
				t.Errorf("authentication request made to incorrect path\nwant: %v\ngot : %v", wantPath, writePathArg)
			}

			wantData := make(map[string]interface{})
			wantData["role_id"] = roleId
			wantData["secret_id"] = secretId

			if !reflect.DeepEqual(writeDataArg, wantData) {
				t.Errorf("incorrect approle authentication request data\nwant: %v\ngot : %v", wantData, writeDataArg)
			}

			if setTokenArg != token {
				t.Errorf("incorrect authentication token added to client\nwant: %v\ngot : %v", token, setTokenArg)
			}
		})
	}
}

func TestOpenTokenEnvVarCreatesAuthenticatedClient(t *testing.T) {
	unsetEnvVars(t)
	defer unsetEnvVars(t)
	want := "a token"
	err := os.Setenv(api.EnvVaultToken, want)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// we can use the constructor as we do not need to mock the client (the client uses the VAULT_TOKEN env var by default)
	s := NewHashicorpService(HashicorpClientConfig{}, nil)
	err = s.open()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	hs := s.(*hashicorpService)
	c := hs.client.(defaultClientDelegate)
	got := c.Token()

	if got != want {
		t.Errorf("default client configured with incorrect token\nwant: %v\ngot : %v", want, got)
	}
}

// unsetEnvVars unsets the vault authentication related environment variables.  To prevent previously ran tests from having an unwanted impact on later tests, it is recommended to call unsetEnvVars at the start of any tests which require the state of these environment variables to be known, and at the end of any tests which change the state of these environment variables.
func unsetEnvVars(t *testing.T) {
	if err := os.Unsetenv(envvars.VaultRoleId); err != nil {
		t.Errorf("unable to unset %v: %v", envvars.VaultRoleId, err)
	}

	if err := os.Unsetenv(envvars.VaultSecretId); err != nil {
		t.Errorf("unable to unset %v: %v", envvars.VaultSecretId, err)
	}

	if err := os.Unsetenv(api.EnvVaultToken); err != nil {
		t.Errorf("unable to unset %v: %v", api.EnvVaultToken, err)
	}
}

func TestCloseReturnsServiceToNewlyCreatedState(t *testing.T) {
	clientConfig := HashicorpClientConfig{Url: "someurl"}
	secrets := []HashicorpSecret{
		{Name: "somesecret"},
	}
	s := NewHashicorpService(clientConfig, secrets)
	// copy so we can compare to initial state
	sCpy := NewHashicorpService(clientConfig, secrets)

	// alter state of hashicorpService
	hs := s.(*hashicorpService)

	if reflect.DeepEqual(fmt.Sprintf("%p", s), fmt.Sprintf("%p", sCpy)) {
		panic("should not be equal")
	}

	hs.acctSecretsByAddress = make(map[common.Address][]acctAndSecret)
	hs.acctSecretsByAddress[common.StringToAddress("someaddress")] = []acctAndSecret{
		{acct: accounts.Account{URL: accounts.URL{"http", "accounturl"}}},
	}
	wasTokenCleared := false
	hs.client = mockClientDelegate{
		clearTokenMock: func() {
			wasTokenCleared = true
		},
	}

	if reflect.DeepEqual(s, sCpy) {
		t.Errorf("state of hashicorpService was not altered as part of test preparation\n%v", s)
	}

	err := s.close()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !wasTokenCleared {
		t.Errorf("token not cleared during Close()")
	}

	//reflect.DeepEqual(a, b) cannot reliably compare functions so set them to nil before doing the DeepEqual comparison
	hs.clientFactory = nil
	sCpy.(*hashicorpService).clientFactory = nil

	if !reflect.DeepEqual(s, sCpy) {
		t.Errorf("Close() did not return state to newly created state\nwant: %v\ngot : %v", sCpy, s)
	}
}

func TestGetAccountsReturnsErrorIfWalletClosed(t *testing.T) {
	s := hashicorpService{}

	accts, errs := s.getAccounts()

	want := []error{
		errors.New("Wallet closed"),
	}

	if accts != nil && reflect.DeepEqual(errs, want) {
		t.Errorf("unexpected result\nwant: %v, %v\ngot : %v, %v", nil, want, accts, errs)
	}
}

func TestGetAccountsErrorsAreReturnedAndDoNotStopFurtherRetrievalFromVault(t *testing.T) {
	secrets := []HashicorpSecret{
		{Name: "secret1", AccountID: "id"}, //client mock will be configured to return valid vault data for this secret
		{Name: "secret2", Version: -1}, // will create an error as version < 0 not allowed
		{Name: "secret3"}, // client mock will be configured to create an error for this secret
		{Name: "secret4", AccountID: "id"}, //client mock will be configured to return valid vault data for this secret
	}

	createErrorPath, _, err := secrets[2].toRequestData()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	mockLogicalDelegate := mockLogicalDelegate{
		readWithDataMock: func(path string, data map[string][]string) (*api.Secret, error) {
			if path != createErrorPath {
				data := make(map[string]interface{})
				dataContents := make(map[string]interface{})
				dataContents["id"] = "4cbB1D65c1441554A1cd96CEC448796C01a46Bb9"

				data["data"] = dataContents

				return &api.Secret{Data: data}, nil
			}
			return nil, errors.New("some error")
		},
	}
	mockSysDelegate := mockSysDelegate{
		healthMock: func() (*api.HealthResponse, error) {
			return &api.HealthResponse{Initialized: true, Sealed: false}, nil
		},
	}
	mockClientDelegate := mockClientDelegate{
		logicalMock: func() logicalDelegate {
			return mockLogicalDelegate
		},
		sysMock: func() sysDelegate {
			return mockSysDelegate
		},
	}
	s := hashicorpService{
		secrets: secrets,
		clientConfig: HashicorpClientConfig{Url: "http://someurl"},
		client: mockClientDelegate,
	}

	accts, errs := s.getAccounts()

	if len(accts) != 2 && len(errs) != 2 {
		t.Errorf("unexpected result\nwant : %v accts and %v errors returned\ngot : %v accts and %v errors returned", 2, 2, len(accts), len(errs))
	}
}

func TestGetAccountUrlCreatesVaultUrlFromSecretData(t *testing.T) {
	secret := HashicorpSecret{Name: "name", SecretEngine: "kv", Version: 4, AccountID: "acctId", KeyID: "keyId"}
	client := HashicorpClientConfig{Url: "http://client"}

	want := accounts.URL{"http", "client/v1/kv/data/name?version=4"}

	s := hashicorpService{clientConfig: client}
	got, err := s.getAccountUrl(secret)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("incorrect url\nwant: %v\ngot : %v", want, got)
	}
}

func TestGetPrivateKeyReturnsErrorIfAccountNotKnown(t *testing.T) {
	addr := common.StringToAddress("addr")
	acct := accounts.Account{
		URL: accounts.URL{"http", "acct"},
		Address: addr,
	}
	secret := HashicorpSecret{}

	a := map[common.Address][]acctAndSecret{
		addr: {
			{ acct:  acct, secret: secret },
		},
	}

	s := hashicorpService{acctSecretsByAddress: a}

	addr2 := common.StringToAddress("otheraddr")
	acct2 := accounts.Account{
		URL: accounts.URL{"http", "acct2"},
		Address: addr2,
	}

	k, err := s.getPrivateKey(acct2)

	if !reflect.DeepEqual(*k, reflect.Zero(reflect.TypeOf(ecdsa.PrivateKey{})).Interface()) {
		t.Errorf("want: %v\ngot : %v", ecdsa.PrivateKey{}, *k)
	}

	if err != accounts.ErrUnknownAccount {
		t.Errorf("unexpected error\nwant: %v\ngot : %v", accounts.ErrUnknownAccount, err)
	}
}

func TestGetPrivateKeyReturnsErrorIfDifferentUrl(t *testing.T) {
	addr := common.StringToAddress("addr")
	acct := accounts.Account{
		URL: accounts.URL{"http", "acct"},
		Address: addr,
	}
	secret := HashicorpSecret{}

	a := map[common.Address][]acctAndSecret{
		addr: {
			{ acct:  acct, secret: secret },
		},
	}

	s := hashicorpService{acctSecretsByAddress: a}

	acct2 := accounts.Account{
		URL: accounts.URL{"http", "acct2"},
		Address: addr,
	}

	k, err := s.getPrivateKey(acct2)

	if !reflect.DeepEqual(*k, reflect.Zero(reflect.TypeOf(ecdsa.PrivateKey{})).Interface()) {
		t.Errorf("want: %v\ngot : %v", ecdsa.PrivateKey{}, *k)
	}

	if err != accounts.ErrUnknownAccount {
		t.Errorf("unexpected error\nwant: %v\ngot : %v", accounts.ErrUnknownAccount, err)
	}
}

func TestGetPrivateKeyUsesAccountWithExactUrlIfProvided(t *testing.T) {
	addr := common.StringToAddress("addr")
	acct := accounts.Account{
		URL: accounts.URL{"http", "acct"},
		Address: addr,
	}
	acct2 := accounts.Account{
		URL: accounts.URL{"http", "acct2"},
		Address: addr,
	}
	secret := HashicorpSecret{ Name: "secret", KeyID: "id" }
	secret2 := HashicorpSecret{ Name: "secret2", KeyID: "id" }

	a := map[common.Address][]acctAndSecret{
		addr: {
			{ acct:  acct, secret: secret },
			{ acct:  acct2, secret: secret2 },
		},
	}

	hexKey := "9676bda387bf2ae687a78afdaaad6f3af8b490b599f42b498b91d5c4c83d1b19"
	mockLogicalDelegate := mockLogicalDelegate{
		readWithDataMock: func(path string, data map[string][]string) (*api.Secret, error) {
			p, _, err := secret2.toRequestData()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if path != p {
				t.Fatalf("incorrect account\nwant: %v\ngot : %v", p, path)
			}

			s := &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"id": hexKey,
					},
				},
			}

			return s, nil
		},
	}
	mockClientDelegate := mockClientDelegate{
		logicalMock: func() logicalDelegate {
			return mockLogicalDelegate
		},
	}
	s := hashicorpService{acctSecretsByAddress: a, client: mockClientDelegate}

	k, err := s.getPrivateKey(acct2)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	want, err := crypto.HexToECDSA(hexKey)

	if !reflect.DeepEqual(k, want) {
		t.Errorf("incorrect key returned\nwant: %v\ngot : %v", want, k)
	}
}

func TestGetPrivateKeyUsesFirstAccountIfNoUrlProvided(t *testing.T) {
	addr := common.StringToAddress("addr")
	acct := accounts.Account{
		URL: accounts.URL{"http", "acct"},
		Address: addr,
	}
	acct2 := accounts.Account{
		URL: accounts.URL{"http", "acct2"},
		Address: addr,
	}
	secret := HashicorpSecret{ Name: "secret", KeyID: "id" }
	secret2 := HashicorpSecret{ Name: "secret2", KeyID: "id" }

	a := map[common.Address][]acctAndSecret{
		addr: {
			{ acct:  acct, secret: secret },
			{ acct:  acct2, secret: secret2 },
		},
	}

	hexKey := "9676bda387bf2ae687a78afdaaad6f3af8b490b599f42b498b91d5c4c83d1b19"
	mockLogicalDelegate := mockLogicalDelegate{
		readWithDataMock: func(path string, data map[string][]string) (*api.Secret, error) {
			p, _, err := secret.toRequestData()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if path != p {
				t.Fatalf("incorrect account\nwant: %v\ngot : %v", p, path)
			}

			s := &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"id": hexKey,
					},
				},
			}

			return s, nil
		},
	}
	mockClientDelegate := mockClientDelegate{
		logicalMock: func() logicalDelegate {
			return mockLogicalDelegate
		},
	}
	s := hashicorpService{acctSecretsByAddress: a, client: mockClientDelegate}

	acct3 := accounts.Account{Address: addr}
	k, err := s.getPrivateKey(acct3)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	want, err := crypto.HexToECDSA(hexKey)

	if !reflect.DeepEqual(k, want) {
		t.Errorf("incorrect key returned\nwant: %v\ngot : %v", want, k)
	}
}

func TestStoreAddsKeyToFirstVaultSecret(t *testing.T) {
	secret := HashicorpSecret{ Name: "secret", AccountID: "acct", KeyID: "key" }
	secret2 := HashicorpSecret{ Name: "secret2", AccountID: "acct", KeyID: "key" }
	addrHex := "B9F4Dd50d705DE54B89492b0A5eeC2817Fe2b390"
	keyHex := "9676bda387bf2ae687a78afdaaad6f3af8b490b599f42b498b91d5c4c83d1b19"

	mockLogicalDelegate := mockLogicalDelegate{
		writeMock: func(path string, data map[string]interface{}) (*api.Secret, error) {
			wantPath, _, err := secret.toRequestData()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if path != wantPath {
				t.Fatalf("incorrect account\nwant: %v\ngot : %v", wantPath, path)
			}
			wantData := make(map[string]interface{})
			wantData["data"] = map[string]interface{}{
				"acct": addrHex,
				"key": keyHex,
			}

			if !reflect.DeepEqual(data, wantData) {
				t.Fatalf("incorrect key data\nwant: %v\ngot : %v", wantData, data)
			}

			return nil, nil
		},
	}
	mockClientDelegate := mockClientDelegate{
		logicalMock: func() logicalDelegate {
			return mockLogicalDelegate
		},
	}
	s := hashicorpService{
		client: mockClientDelegate,
		secrets: []HashicorpSecret{ secret, secret2 },
	}

	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	addr, err := s.store(key)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if addr != common.HexToAddress(addrHex) {
		t.Errorf("incorrect address returned\nwant: %v\ngot : %v", addrHex, addr)
	}
}

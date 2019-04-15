package vault
//
//import (
//	"errors"
//	"fmt"
//	"github.com/ethereum/go-ethereum/accounts"
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/crypto"
//	"github.com/ethereum/go-ethereum/event"
//	"github.com/hashicorp/vault/api"
//	"os"
//	"reflect"
//	"testing"
//)
//
//type clientMock struct {
//	response *api.HealthResponse
//	token string
//	err error
//	r readWithDataMock
//}
//
//func (c *clientMock) SetAddress(addr string) error {
//	return nil
//}
//
//func (c *clientMock) SetToken(v string) {
//	c.token = v
//}
//
//func (c *clientMock) ClearToken() {
//	panic("implement me")
//}
//
//func (c *clientMock) Logical() logicalI {
//	return &logicalMock{r: c.r}
//}
//
//func (c *clientMock) Sys() sysI {
//	return &sysMock{c.response, c.err}
//}
//
//type logicalMock struct {
//	r readWithDataMock
//}
//
//type readWithDataMock = func(path string, data map[string][]string) (*api.Secret, error)
//
//const (
//	approletoken = "approletoken"
//	defaulttoken = "defaulttoken"
//)
//
//func (logicalMock) Write(path string, data map[string]interface{}) (*api.Secret, error) {
//	auth := &api.SecretAuth{ClientToken: approletoken}
//	response := &api.Secret{Auth: auth}
//
//	return response, nil
//}
//
//func (l logicalMock) ReadWithData(path string, data map[string][]string) (*api.Secret, error) {
//	return l.r(path, data)
//}
//
//type sysMock struct {
//	response *api.HealthResponse
//	err error
//}
//
//func (s sysMock) Health() (*api.HealthResponse, error) {
//	return s.response, s.err
//}
//
//func TestStatusChecksWalletHasClient(t *testing.T) {
//	hw := hashicorpWallet{}
//
//	got, err := hw.Status()
//
//	if err != nil {
//		t.Errorf("Error %v", err)
//	}
//
//	want := walletClosed
//	if got != want {
//		t.Errorf("want %v, got %v", want, got)
//	}
//}
//
//var statusTests = []struct {
//	name string
//	client clientMock
//	wantMsg string
//	wantErr error
//} {
//	{
//		"Error if client health check fails",
//		clientMock{
//			response: &api.HealthResponse{Initialized: true, Sealed: true},
//			err: errors.New("some error"),
//		},
//		healthcheckFailed,
//		errors.New("some error"),
//	},
//	{
//		"Vault uninitialized",
//		clientMock{
//			response: &api.HealthResponse{Initialized: false, Sealed: true},
//			err: nil,
//		},
//		vaultUninitialised,
//		fmt.Errorf("Vault health check result - Initialized: false, Sealed: true"),
//	},
//	{
//		"Vault sealed",
//		clientMock{
//			response: &api.HealthResponse{Initialized: true, Sealed: true},
//			err: nil,
//		},
//		vaultSealed,
//		fmt.Errorf("Vault health check result - Initialized: true, Sealed: true"),
//	},
//	{
//		"Wallet open",
//		clientMock{
//			response: &api.HealthResponse{Initialized: true, Sealed: false},
//			err: nil,
//		},
//		walletOpen,
//		nil,
//	},
//}
//func TestStatusChecksVaultInitializedAndUnsealed(t *testing.T) {
//
//	for _, tt := range statusTests {
//		t.Run(tt.name, func(t *testing.T) {
//			hw := hashicorpWallet{client: &tt.client}
//
//			gotMsg, gotErr := hw.Status()
//
//			if gotMsg != tt.wantMsg {
//				t.Errorf("Incorrect status returned\nwant: %q\ngot : %q", tt.wantMsg, gotMsg)
//			}
//
//			if (gotErr == nil && tt.wantErr != nil) || (gotErr != nil && tt.wantErr == nil)  ||
//				(gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error()) {
//				t.Errorf("Incorrect error returned\nwant: %q\ngot : %q", tt.wantErr, gotErr)
//			}
//		})
//	}
//}
//
//var openTests = []struct {
//	name string
//	setRoleID bool
//	setSecretID bool
//	hw hashicorpWallet
//	want error
//} {
//	{
//		name: "Do not reopen if wallet already has client",
//		hw: hashicorpWallet{client: &clientMock{}},
//		want: accounts.ErrWalletAlreadyOpen,
//	},
//	{
//		name: "Role id env var set but secret id not set",
//		hw: hashicorpWallet{clientFactory: mockFactory{}},
//		setRoleID: true,
//		setSecretID: false,
//		want: fmt.Errorf("both %q and %q environment variables must be set to use Approle authentication", vaultRoleId, vaultSecretId),
//	},
//	{
//		name: "Secret id env var set but role id not set",
//		hw: hashicorpWallet{clientFactory: mockFactory{}},
//		setRoleID: false,
//		setSecretID: true,
//		want: fmt.Errorf("both %q and %q environment variables must be set to use Approle authentication", vaultRoleId, vaultSecretId),
//	},
//}
//func TestOpenErrors(t *testing.T) {
//	for _, tt := range openTests {
//		t.Run(tt.name, func(t *testing.T) {
//			if tt.setRoleID {
//				if err := os.Setenv(vaultRoleId, "role-id"); err != nil {
//					t.Errorf("unable to set %q", vaultRoleId)
//				}
//				defer unsetenv(t, vaultRoleId)
//			}
//
//			if tt.setSecretID {
//				if err := os.Setenv(vaultSecretId, "secret-id"); err != nil {
//					t.Errorf("unable to set %q", vaultSecretId)
//				}
//				defer unsetenv(t, vaultSecretId)
//			}
//
//			got := tt.hw.Open("")
//
//			if got.Error() != tt.want.Error() {
//				t.Errorf("\nwant: %v\ngot : %v", tt.want, got)
//			}
//		})
//	}
//}
//
//func TestOpenUsesApproleOverToken(t *testing.T) {
//	if err := os.Setenv(api.EnvVaultToken, "defaulttoken"); err != nil {
//		t.Errorf("unable to set %q", vaultRoleId)
//	}
//	defer unsetenv(t, vaultRoleId)
//
//	if err := os.Setenv(vaultRoleId, "role-id"); err != nil {
//		t.Errorf("unable to set %q", vaultRoleId)
//	}
//	defer unsetenv(t, vaultRoleId)
//
//	if err := os.Setenv(vaultSecretId, "secret-id"); err != nil {
//		t.Errorf("unable to set %q", vaultSecretId)
//	}
//	defer unsetenv(t, vaultSecretId)
//
//	hw := hashicorpWallet{updateFeed: &event.Feed{}, clientFactory: mockFactory{}}
//	if err := hw.Open(""); err != nil {
//		t.Errorf("unwanted error %v", err)
//	}
//
//	client := hw.client.(*clientMock)
//	if client.token != approletoken {
//		t.Errorf("client should be using approle token\nwant: %v\ngot : %v", approletoken, client.token)
//	}
//}
//
//func unsetenv(t *testing.T, key string) {
//	if err := os.Unsetenv(key); err != nil {
//		t.Errorf("unable to unset %q", key)
//	}
//}
//
//type mockFactory struct {
//
//}
//
//func (mockFactory) create() (clientI, error) {
//	return &clientMock{}, nil
//}
//
//func TestCloseReturnsStateToSameAsBeforeOpen(t *testing.T) {
//	hw, err := NewWallet(
//		ClientConfig{Url: "http://someurl"},
//		[]Secret{{Name: "somesecret"}},
//		&event.Feed{},
//	)
//
//	if err != nil {
//		t.Errorf("unexpected error %v", err)
//	}
//
//	if err = os.Setenv(api.EnvVaultToken, "token"); err != nil {
//		t.Error(err)
//	}
//	defer unsetenv(t, api.EnvVaultToken)
//
//	initialHw := *hw
//
//	if err = hw.Open(""); err != nil {
//		t.Errorf("unable to open wallet %v", err)
//	}
//
//	openHw := *hw
//
//	if reflect.DeepEqual(initialHw, openHw) {
//		t.Errorf("wallet state should have changed after Open(...)\ninit: %+v\ngot : %+v", initialHw, openHw)
//	}
//
//	if err = hw.Close(); err != nil {
//		t.Errorf("unable to close wallet %v", err)
//	}
//
//	closedHw := *hw
//
//	if !reflect.DeepEqual(initialHw, closedHw) {
//		t.Errorf("wallet state should have returned to initial after Close()\ninit: %+v\ngot : %+v", initialHw, closedHw)
//	}
//}
//
//func TestCloseDoesNothingIfNoClientInWallet(t *testing.T) {
//	hw, err := NewWallet(
//		ClientConfig{Url: "http://someurl"},
//		[]Secret{{Name: "somesecret"}},
//		&event.Feed{},
//	)
//
//	if err != nil {
//		t.Errorf("unexpected error %v", err)
//	}
//
//	initialHw := *hw
//
//	if err = hw.Close(); err != nil {
//		t.Errorf("unable to close wallet %v", err)
//	}
//
//	closedHw := *hw
//
//	if !reflect.DeepEqual(initialHw, closedHw) {
//		t.Errorf("wallet state should not have changed after Close()\ninit: %v\ngot : %v", initialHw, closedHw)
//	}
//}
//
//func TestAccountsReturnsCopyToPreventChangingWalletState(t *testing.T) {
//	addr1 := common.StringToAddress("someaddress")
//	addr2 := common.StringToAddress("anotheraddress")
//
//	accts := []accounts.Account{
//		{Address: addr1},
//		{Address: addr2},
//	}
//	hw := hashicorpWallet{accounts: accts}
//
//	want := accts
//	got := hw.Accounts()
//
//	if !reflect.DeepEqual(want, got) {
//		t.Errorf("unexpected result\nwant: %+v\ngot : %+v", want, got)
//	}
//
//	addr3 := common.StringToAddress("thirdaddress")
//	got[0].Address = addr3
//
//	if reflect.DeepEqual(got, hw.accounts) {
//		t.Errorf("changing the slice returned by Accounts() should not have changed the slice in the wallet itself\nwant: %v\ngot : %v",
//			[]accounts.Account{
//				{Address: addr1},
//				{Address: addr2},
//			},
//			got)
//	}
//}
//
//var containsTests = []struct {
//	name string
//	wltAccts []accounts.Account
//	target accounts.Account
//	want bool
//} {
//	{
//		name: "Wallet contains account with same address and URL as target",
//		wltAccts: []accounts.Account{
//			{
//				common.StringToAddress("someaddress"),
//				accounts.URL{"http", "someurl"},
//			},
//			{
//				common.StringToAddress("altaddress"),
//				accounts.URL{"http", "alturl"},
//			},
//		},
//		target: accounts.Account {
//			common.StringToAddress("someaddress"),
//			accounts.URL{"http", "someurl"},
//		},
//		want: true,
//	},
//	{
//		name: "Wallet contains account with same address and zero value URL as target",
//		wltAccts: []accounts.Account{
//			{
//				common.StringToAddress("someaddress"),
//				accounts.URL{},
//			},
//			{
//				common.StringToAddress("altaddress"),
//				accounts.URL{"http", "alturl"},
//			},
//		},
//		target: accounts.Account {
//			common.StringToAddress("someaddress"),
//			accounts.URL{},
//		},
//		want: true,
//	},
//	{
//		name: "Wallet contains account with same address but only wallet acct has zero value URL",
//		wltAccts: []accounts.Account{
//			{
//				common.StringToAddress("someaddress"),
//				accounts.URL{},
//			},
//			{
//				common.StringToAddress("altaddress"),
//				accounts.URL{"http", "alturl"},
//			},
//		},
//		target: accounts.Account {
//			common.StringToAddress("someaddress"),
//			accounts.URL{"http", "someurl"},
//		},
//		want: false,
//	},
//	{
//		name: "Wallet contains account with same address but only target acct has zero value URL",
//		wltAccts: []accounts.Account{
//			{
//				common.StringToAddress("someaddress"),
//				accounts.URL{"http", "someurl"},
//			},
//			{
//				common.StringToAddress("altaddress"),
//				accounts.URL{"http", "alturl"},
//			},
//		},
//		target: accounts.Account {
//			common.StringToAddress("someaddress"),
//			accounts.URL{},
//		},
//		want: true,
//	},
//	{
//		name: "Wallet contains account with same address but different URL",
//		wltAccts: []accounts.Account{
//			{
//				common.StringToAddress("someaddress"),
//				accounts.URL{"http", "someurl"},
//			},
//			{
//				common.StringToAddress("altaddress"),
//				accounts.URL{"http", "alturl"},
//			},
//		},
//		target: accounts.Account {
//			common.StringToAddress("someaddress"),
//			accounts.URL{"http", "anotherurl"},
//		},
//		want: false,
//	},
//	{
//		name: "Wallet contains account with different address but same URL",
//		wltAccts: []accounts.Account{
//			{
//				common.StringToAddress("someaddress"),
//				accounts.URL{"http", "someurl"},
//			},
//			{
//				common.StringToAddress("altaddress"),
//				accounts.URL{"http", "alturl"},
//			},
//		},
//		target: accounts.Account {
//			common.StringToAddress("anotheraddress"),
//			accounts.URL{"http", "someurl"},
//		},
//		want: false,
//	},
//	{
//		name: "Wallet does not contain account with same address or URL",
//		wltAccts: []accounts.Account{
//			{
//				common.StringToAddress("someaddress"),
//				accounts.URL{"http", "someurl"},
//			},
//			{
//				common.StringToAddress("altaddress"),
//				accounts.URL{"http", "alturl"},
//			},
//		},
//		target: accounts.Account {
//			common.StringToAddress("anotheraddress"),
//			accounts.URL{"http", "anotherurl"},
//		},
//		want: false,
//	},
//
//}
//func TestContains(t *testing.T) {
//	for _, tt := range containsTests {
//		t.Run(tt.name, func(t *testing.T) {
//			hw := hashicorpWallet{accounts: tt.wltAccts}
//			got := hw.Contains(tt.target)
//
//			if got != tt.want {
//				t.Errorf("Incorrect result from Contains()\nwant: %v\ngot : %v", tt.want, got)
//			}
//		})
//	}
//}
//
//func TestGetAccount(t *testing.T) {
//	acct := "cb2b4a9afb2c14da442d7a39aa38d13c913ee4b0"
//	clientUrl := "http://clienturl"
//
//	mockReadWithData := func(path string, data map[string][]string) (*api.Secret, error) {
//		m := make(map[string]interface{})
//		m["account"] = acct
//
//		fromVault := make(map[string]interface{})
//		fromVault["data"] = m
//
//		return &api.Secret{Data: fromVault}, nil
//	}
//
//	hw := hashicorpWallet{
//		client: &clientMock{
//			r: mockReadWithData,
//		},
//		clientData: ClientConfig{
//			Url: clientUrl,
//		},
//	}
//
//	secret := Secret{Name: "name", SecretEngine: "engine", Version: 0, AccountID: "account", KeyID: "key"}
//
//	got, err := hw.getAccount(secret)
//
//	if err != nil {
//		t.Errorf("unexpected error %v", err)
//	}
//
//	want := accounts.Account{
//		Address: common.HexToAddress(acct),
//		URL: accounts.URL{"http", "clienturl/v1/engine/data/name?version=0"},
//	}
//
//	if got != want {
//		t.Errorf("incorrect value returned\nwant: %v\ngot : %v", want, got)
//	}
//}
//
//func TestGetPrivateKey(t *testing.T) {
//	key := "4eb2ffc002a3a6c009f883a7209517ffd26dd631e3baeed2e88334ff4f88dd2e"
//	clientUrl := "http://clienturl"
//
//	mockReadWithData := func(path string, data map[string][]string) (*api.Secret, error) {
//		m := make(map[string]interface{})
//		m["key"] = key
//
//		fromVault := make(map[string]interface{})
//		fromVault["data"] = m
//
//		return &api.Secret{Data: fromVault}, nil
//	}
//
//	hw := hashicorpWallet{
//		client: &clientMock{
//			r: mockReadWithData,
//		},
//		clientData: ClientConfig{
//			Url: clientUrl,
//		},
//	}
//
//	secret := Secret{Name: "name", SecretEngine: "engine", Version: 0, AccountID: "account", KeyID: "key"}
//
//	got, err := hw.getPrivateKey(secret)
//
//	if err != nil {
//		t.Errorf("unexpected error %v", err)
//	}
//
//	want, err := crypto.HexToECDSA(key)
//
//	if err != nil {
//		t.Errorf("unexpected error %v", err)
//	}
//
//	if !reflect.DeepEqual(got, want) {
//		t.Errorf("incorrect value returned\nwant: %+v\ngot : %+v", want, got)
//	}
//}
//

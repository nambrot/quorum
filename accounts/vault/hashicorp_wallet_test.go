package vault

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/hashicorp/vault/api"
	"os"
	"reflect"
	"testing"
)

type clientMock struct {
	response *api.HealthResponse
	token string
	err error
}

func (c *clientMock) SetAddress(addr string) error {
	return nil
}

func (c *clientMock) SetToken(v string) {
	c.token = v
}

func (c *clientMock) ClearToken() {
	panic("implement me")
}

func (*clientMock) Logical() logicalI {
	return &logicalMock{}
}

func (c *clientMock) Sys() sysI {
	return &sysMock{c.response, c.err}
}

type logicalMock struct {

}
const (
	approletoken = "approletoken"
	defaulttoken = "defaulttoken"
)

func (logicalMock) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	auth := &api.SecretAuth{ClientToken: approletoken}
	response := &api.Secret{Auth: auth}

	return response, nil
}

func (logicalMock) ReadWithData(path string, data map[string][]string) (*api.Secret, error) {
	d := make(map[string]interface{})
	d["path"] = path
	d["data"] = data

	return &api.Secret{Data: d}, nil
}

type sysMock struct {
	response *api.HealthResponse
	err error
}

func (s sysMock) Health() (*api.HealthResponse, error) {
	return s.response, s.err
}

func TestStatusChecksWalletHasClient(t *testing.T) {
	hw := hashicorpWallet{}

	got, err := hw.Status()

	if err != nil {
		t.Errorf("Error %v", err)
	}

	want := walletClosed
	if got != want {
		t.Errorf("want %v, got %v", want, got)
	}
}

var statusTests = []struct {
	name string
	client clientMock
	wantMsg string
	wantErr error
} {
	{
		"Error if client health check fails",
		clientMock{
			response: &api.HealthResponse{Initialized: true, Sealed: true},
			err: errors.New("some error"),
		},
		healthcheckFailed,
		errors.New("some error"),
	},
	{
		"Vault uninitialized",
		clientMock{
			response: &api.HealthResponse{Initialized: false, Sealed: true},
			err: nil,
		},
		vaultUninitialised,
		fmt.Errorf("Vault health check result - Initialized: false, Sealed: true"),
	},
	{
		"Vault sealed",
		clientMock{
			response: &api.HealthResponse{Initialized: true, Sealed: true},
			err: nil,
		},
		vaultSealed,
		fmt.Errorf("Vault health check result - Initialized: true, Sealed: true"),
	},
	{
		"Wallet open",
		clientMock{
			response: &api.HealthResponse{Initialized: true, Sealed: false},
			err: nil,
		},
		walletOpen,
		nil,
	},
}
func TestStatusChecksVaultInitializedAndUnsealed(t *testing.T) {

	for _, tt := range statusTests {
		t.Run(tt.name, func(t *testing.T) {
			hw := hashicorpWallet{client: &tt.client}

			gotMsg, gotErr := hw.Status()

			if gotMsg != tt.wantMsg {
				t.Errorf("Incorrect status returned\nwant: %q\ngot : %q", tt.wantMsg, gotMsg)
			}

			if (gotErr == nil && tt.wantErr != nil) || (gotErr != nil && tt.wantErr == nil)  ||
				(gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error()) {
				t.Errorf("Incorrect error returned\nwant: %q\ngot : %q", tt.wantErr, gotErr)
			}
		})
	}
}

var openTests = []struct {
	name string
	setRoleID bool
	setSecretID bool
	hw hashicorpWallet
	want error
} {
	{
		name: "Do not reopen if wallet already has client",
		hw: hashicorpWallet{client: &clientMock{}},
		want: accounts.ErrWalletAlreadyOpen,
	},
	{
		name: "Role id env var set but secret id not set",
		hw: hashicorpWallet{clientFactory: mockFactory{}},
		setRoleID: true,
		setSecretID: false,
		want: fmt.Errorf("both %q and %q environment variables must be set to use Approle authentication", vaultRoleId, vaultSecretId),
	},
	{
		name: "Secret id env var set but role id not set",
		hw: hashicorpWallet{clientFactory: mockFactory{}},
		setRoleID: false,
		setSecretID: true,
		want: fmt.Errorf("both %q and %q environment variables must be set to use Approle authentication", vaultRoleId, vaultSecretId),
	},
}
func TestOpenErrors(t *testing.T) {
	for _, tt := range openTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setRoleID {
				if err := os.Setenv(vaultRoleId, "role-id"); err != nil {
					t.Errorf("unable to set %q", vaultRoleId)
				}
				defer unsetenv(t, vaultRoleId)
			}

			if tt.setSecretID {
				if err := os.Setenv(vaultSecretId, "secret-id"); err != nil {
					t.Errorf("unable to set %q", vaultSecretId)
				}
				defer unsetenv(t, vaultSecretId)
			}

			got := tt.hw.Open("")

			if got.Error() != tt.want.Error() {
				t.Errorf("\nwant: %v\ngot : %v", tt.want, got)
			}
		})
	}
}

func TestOpenUsesApproleOverToken(t *testing.T) {
	if err := os.Setenv(api.EnvVaultToken, "defaulttoken"); err != nil {
		t.Errorf("unable to set %q", vaultRoleId)
	}
	defer unsetenv(t, vaultRoleId)

	if err := os.Setenv(vaultRoleId, "role-id"); err != nil {
		t.Errorf("unable to set %q", vaultRoleId)
	}
	defer unsetenv(t, vaultRoleId)

	if err := os.Setenv(vaultSecretId, "secret-id"); err != nil {
		t.Errorf("unable to set %q", vaultSecretId)
	}
	defer unsetenv(t, vaultSecretId)

	hw := hashicorpWallet{updateFeed: &event.Feed{}, clientFactory: mockFactory{}}
	if err := hw.Open(""); err != nil {
		t.Errorf("unwanted error %v", err)
	}

	client := hw.client.(*clientMock)
	if client.token != approletoken {
		t.Errorf("client should be using approle token\nwant: %v\ngot : %v", approletoken, client.token)
	}
}

func unsetenv(t *testing.T, key string) {
	if err := os.Unsetenv(key); err != nil {
		t.Errorf("unable to unset %q", key)
	}
}

type mockFactory struct {

}

func (mockFactory) create() (clientI, error) {
	return &clientMock{}, nil
}

func TestCloseReturnsStateToSameAsBeforeOpen(t *testing.T) {
	hw, err := NewHashicorpWallet(
		ClientData{Url: "http://someurl"},
		[]SecretData{{Name: "somesecret"}},
		&event.Feed{},
	)

	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	if err = os.Setenv(api.EnvVaultToken, "token"); err != nil {
		t.Error(err)
	}
	defer unsetenv(t, api.EnvVaultToken)

	initialHw := *hw

	if err = hw.Open(""); err != nil {
		t.Errorf("unable to open wallet %v", err)
	}

	openHw := *hw

	if reflect.DeepEqual(initialHw, openHw) {
		t.Errorf("wallet state should have changed after Open(...)\ninit: %+v\ngot : %+v", initialHw, openHw)
	}

	if err = hw.Close(); err != nil {
		t.Errorf("unable to close wallet %v", err)
	}

	closedHw := *hw

	if !reflect.DeepEqual(initialHw, closedHw) {
		t.Errorf("wallet state should have returned to initial after Close()\ninit: %+v\ngot : %+v", initialHw, closedHw)
	}
}

func TestCloseDoesNothingIfNoClientInWallet(t *testing.T) {
	panic("implement me")
}

//func TestRead(t *testing.T) {
//	c := clientMock{}
//	hw := hashicorpWallet{client: c}
//
//	secretEngineName, secretName := "engine", "name"
//	secretVersion := 1
//
//	secret, err := hw.read(secretEngineName, secretName, secretVersion)
//
//	if(err != nil) {
//		t.Errorf("Error %v", err)
//	}
//
//	path, pok := secret.Data["path"]
//	data, dok := secret.Data["data"]
//
//
//	if(!pok || !dok) {
//		t.Errorf("Expected map returned from mock test object to include path and data keys")
//	}
//
//	expectedPath := secretEngineName + "/data/" + secretName
//
//	if(path != expectedPath) {
//		t.Errorf("Incorrect path created by Read\nwant: %v\ngot : %v", expectedPath, path)
//	}
//
//	expectedData := make(map[string][]string)
//	expectedData["version"] = []string{strconv.Itoa(secretVersion)}
//
//	if(!reflect.DeepEqual(data, expectedData)) {
//		t.Errorf("Incorrect query param data created by Read\nwant: %v\ngot : %v", expectedData, data)
//	}
//}
//
//var readVersionTests = []struct {
//	version int
//	wantErr bool
//} {
//	{0, false},
//	{1, false},
//	{-1, true},
//}
//func TestReadVersionMustBe0OrPositiveInteger(t *testing.T) {
//	c := clientMock{}
//	hw := hashicorpWallet{client: c}
//
//	engine, name := "engine", "name"
//
//	for _, tt := range readVersionTests {
//		t.Run(fmt.Sprintf("%d", tt.version), func(t *testing.T) {
//			_, err := hw.read(engine, name, tt.version)
//
//			if tt.wantErr == (err == nil) {
//				t.Errorf("version = %v not handled as expected\nwant: error = %v\ngot : error %#v", tt.version, tt.wantErr, err)
//			}
//		})
//	}
//}
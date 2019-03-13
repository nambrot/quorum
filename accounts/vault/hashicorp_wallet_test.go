package vault

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"reflect"
	"strconv"
	"testing"
)

type clientMock struct {
	healthResponse *api.HealthResponse
	err error
}

func (clientMock) doLogical() logicalInterface {
	return logicalMock{}
}

func (c clientMock) doSys() sysInterface {
	return sysMock{c.healthResponse, c.err}
}

func (clientMock) doSetToken(token string) {
	panic("implement me")
}

func (clientMock) doClearToken() {
	panic("implement me")
}

type logicalMock struct {
	// empty
}

func (logicalMock) doReadWithData(path string, data map[string][]string) (*api.Secret, error) {
	d := make(map[string]interface{})

	d["path"] = path
	d["data"] = data

	return &api.Secret{Data: d}, nil
}

func (logicalMock) doWrite(path string, data map[string]interface{}) (*api.Secret, error) {
	panic("implement me")
}

type sysMock struct {
	response *api.HealthResponse
	err error
}

func (s sysMock) doHealth() (*api.HealthResponse, error) {
	return s.response, s.err
}

func TestStatusChecksWalletHasClient(t *testing.T) {
	hw := hashicorpWallet{}

	got, err := hw.Status()

	if err != nil {
		t.Errorf("Error %v", err)
	}

	want := "Closed"
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
		"Status error if client health check fails",
		clientMock{
			&api.HealthResponse{Initialized: true, Sealed: true},
			errors.New("some error"),
		},
		"Vault unable to perform healthcheck",
		errors.New("some error"),
	},
	{
		"Vault uninitialized",
		clientMock{
			&api.HealthResponse{Initialized: false, Sealed: true},
			nil,
		},
		"Vault uninitialized",
		fmt.Errorf("Vault health check, Initialized: false, Sealed: true"),
	},
	{
		"Vault sealed",
		clientMock{
			&api.HealthResponse{Initialized: true, Sealed: true},
			nil,
		},
		"Vault sealed",
		fmt.Errorf("Vault health check, Initialized: true, Sealed: true"),
	},
	{
		"Vault okay",
		clientMock{
			&api.HealthResponse{Initialized: true, Sealed: false},
			nil,
		},
		"Vault initialized and unsealed",
		nil,
	},
}
func TestStatusChecksVaultInitializedAndUnsealed(t *testing.T) {

	for _, tt := range statusTests {
		t.Run(tt.name, func(t *testing.T) {
			hw := hashicorpWallet{client: tt.client}

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

func TestRead(t *testing.T) {
	c := clientMock{}
	hw := hashicorpWallet{client: c}

	secretEngineName, secretName := "engine", "name"
	secretVersion := 1

	secret, err := hw.read(secretEngineName, secretName, secretVersion)

	if(err != nil) {
		t.Errorf("Error %v", err)
	}

	path, pok := secret.Data["path"]
	data, dok := secret.Data["data"]


	if(!pok || !dok) {
		t.Errorf("Expected map returned from mock test object to include path and data keys")
	}

	expectedPath := secretEngineName + "/data/" + secretName

	if(path != expectedPath) {
		t.Errorf("Incorrect path created by Read\nwant: %v\ngot : %v", expectedPath, path)
	}

	expectedData := make(map[string][]string)
	expectedData["version"] = []string{strconv.Itoa(secretVersion)}

	if(!reflect.DeepEqual(data, expectedData)) {
		t.Errorf("Incorrect query param data created by Read\nwant: %v\ngot : %v", expectedData, data)
	}
}

var readVersionTests = []struct {
	version int
	wantErr bool
} {
	{0, false},
	{1, false},
	{-1, true},
}
func TestReadVersionMustBe0OrPositiveInteger(t *testing.T) {
	c := clientMock{}
	hw := hashicorpWallet{client: c}

	engine, name := "engine", "name"

	for _, tt := range readVersionTests {
		t.Run(fmt.Sprintf("%d", tt.version), func(t *testing.T) {
			_, err := hw.read(engine, name, tt.version)

			if tt.wantErr == (err == nil) {
				t.Errorf("version = %v not handled as expected\nwant: error = %v\ngot : error %#v", tt.version, tt.wantErr, err)
			}
		})
	}
}
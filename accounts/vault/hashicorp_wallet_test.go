package vault

import (
	"github.com/hashicorp/vault/api"
	"reflect"
	"strconv"
	"testing"
)

type clientMock struct {
	// empty
}

func (clientMock) doLogical() logicalInterface {
	return logicalMock{}
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

func TestRead(t *testing.T) {
	c := clientMock{}
	hw := hashicorpWallet{client: c}

	secretEngineName, secretName := "engine", "name"
	secretVersion := 1

	secret, err := hw.read(secretEngineName, secretName, secretVersion)

	if(err != nil) {
		t.Errorf("Test failed: Error %v", err)
	}

	path, pok := secret.Data["path"]
	data, dok := secret.Data["data"]


	if(!pok || !dok) {
		t.Errorf("Expected map returned from mock test object to include path and data keys")
	}

	expectedPath := secretEngineName + "/data/" + secretName

	if(path != expectedPath) {
		t.Errorf("Incorrect path created by Read: expected %v, actual %v", expectedPath, path)
	}

	expectedData := make(map[string][]string)
	expectedData["version"] = []string{strconv.Itoa(secretVersion)}

	if(!reflect.DeepEqual(data, expectedData)) {
		t.Errorf("Incorrect query param data created by Read: expected %v, actual %v", expectedData, data)
	}
}

var readVersionTable = []struct {
	version int
	ok bool
} {
	{0, true},
	{1, true},
	{-1, false},
}
func TestReadVersionMustBe0OrPositiveInteger(t *testing.T) {
	c := clientMock{}
	hw := hashicorpWallet{client: c}

	engine, name := "engine", "name"

	for _, entry := range readVersionTable {
		_, err := hw.read(engine, name, entry.version)

		if (entry.ok && err != nil) || (!entry.ok && err == nil) {
			t.Errorf("Version %v was not handled as expected: expected ok = %v, actual error \"%s\"", entry.version, entry.ok, err)
		}
	}

}
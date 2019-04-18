package vault

import "github.com/hashicorp/vault/api"

type clientDelegate interface {
	Logical() logicalDelegate
	Sys() sysDelegate
	SetAddress(addr string) error
	SetToken(v string)
	ClearToken()
}

type logicalDelegate interface{
	ReadWithData(path string, data map[string][]string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

type sysDelegate interface{
	Health() (*api.HealthResponse, error)
}

type defaultClientDelegate struct {
	*api.Client
}

func (cd defaultClientDelegate) Logical() logicalDelegate {
	return cd.Client.Logical()
}

func (cd defaultClientDelegate) Sys() sysDelegate {
	return cd.Client.Sys()
}

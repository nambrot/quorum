package hashicorp

import "github.com/hashicorp/vault/api"

type clientI interface {
	Logical() logicalI
	Sys() sysI
	SetAddress(addr string) error
	SetToken(v string)
	ClearToken()
}

type logicalI interface{
	ReadWithData(path string, data map[string][]string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

type sysI interface{
	Health() (*api.HealthResponse, error)
}

type clientDelegate struct {
	*api.Client
}

func (cd clientDelegate) Logical() logicalI {
	return cd.Client.Logical()
}

func (cd clientDelegate) Sys() sysI {
	return cd.Client.Sys()
}

type clientFactory interface {
	create() (clientI, error)
}

type defaultClientFactory struct {

}

func (defaultClientFactory) create() (clientI, error) {
	conf := api.DefaultConfig()
	client, err := api.NewClient(conf)

	if err != nil {
		return nil, err
	}

	return clientDelegate{client}, nil
}
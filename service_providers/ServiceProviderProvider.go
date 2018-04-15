package service_providers

import (
	"net/http"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"fmt"
	"github.com/crewjam/saml/logger"
)

type InMemoryServiceProviderProvider struct {
	Logger logger.Interface
	Store  *samlidp.MemoryStore
}

func (imp InMemoryServiceProviderProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	service := samlidp.Service{}
	err := imp.Store.Get(fmt.Sprintf("/services/%s", serviceProviderID), &service)
	if err != nil {
		imp.Logger.Printf("ERROR: %s", err)
		return nil, err
	}
	return &service.Metadata, nil
}

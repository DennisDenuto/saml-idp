package service_providers

import (
	"github.com/crewjam/saml"
	"io"
	"encoding/xml"
	"errors"
	"io/ioutil"
)

func GetSPMetadata(r io.Reader) (spMetadata *saml.EntityDescriptor, err error) {
	var bytes []byte

	if bytes, err = ioutil.ReadAll(r); err != nil {
		return nil, err
	}

	spMetadata = &saml.EntityDescriptor{}

	if err := xml.Unmarshal(bytes, &spMetadata); err != nil {
		if err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}

			if err := xml.Unmarshal(bytes, &entities); err != nil {
				return nil, err
			}

			for _, e := range entities.EntityDescriptors {
				if len(e.SPSSODescriptors) > 0 {
					return &e, nil
				}
			}

			// there were no SPSSODescriptors in the response
			return nil, errors.New("metadata contained no service provider metadata")
		}

		return nil, err
	}

	return spMetadata, nil
}

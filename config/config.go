package config

import "encoding/json"
import (
	"gopkg.in/validator.v2"
	"fmt"
)

type Config struct {
	PrivateKey                 string   `json:"private_key" validate:"nonzero"`
	Certificate                string   `json:"certificate" validate:"nonzero"`
	Address                    string   `json:"address" validate:"nonzero"`
	ServiceProviderMetadataURL []string `json:"sp_metadata_urls"`
}

func NewConfig(configContent []byte) (*Config, error) {

	config := &Config{}
	err := json.Unmarshal(configContent, config)
	if err != nil {
		panic(err)
	}
	if err = validator.Validate(config); err != nil {
		return nil, fmt.Errorf("invalid config %s", err)
	}

	return config, err
}

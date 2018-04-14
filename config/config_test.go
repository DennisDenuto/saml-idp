package config_test

import (
	. "github.com/DennisDenuto/saml-idp/config"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/ginkgo/extensions/table"
	"encoding/json"
)

var _ = Describe("Config", func() {
	var config *Config
	var err error
	BeforeEach(func() {
		config, err = NewConfig([]byte(`{
					"address": "http://localhost",
					"private_key": "abc",
					"certificate": "def",
					"sp_metadata_urls": {
						"sp_name": "http://someurl",
						"sp_name2": "http://someurl2"
					}
				}`))
	})

	It("should generate config from json config file", func() {
		Expect(err).NotTo(HaveOccurred())
		Expect(config.PrivateKey).To(Equal("abc"))
		Expect(config.Certificate).To(Equal("def"))
		Expect(config.Certificate).To(Equal("def"))
		Expect(config.Address).To(Equal("http://localhost"))
		Expect(config.ServiceProviderMetadataURLs).To(HaveKeyWithValue("sp_name", "http://someurl"))
		Expect(config.ServiceProviderMetadataURLs).To(HaveKeyWithValue("sp_name2", "http://someurl2"))
	})

	Context("when given an invalid json config file", func() {
		var requiredFields map[string]string

		BeforeEach(func() {
			requiredFields = map[string]string{
				"address":     "address",
				"private_key": "key",
				"certificate": "cert",
			}
		})

		table.DescribeTable("invalid fields", func(invalidKey, invalidValue, errorDescription string) {
			cfg := cloneMap(requiredFields)

			cfg[invalidKey] = invalidValue

			jsonBytes, err := json.Marshal(cfg)
			Expect(err).NotTo(HaveOccurred())

			_, err = NewConfig(jsonBytes)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(errorDescription))

		},
			table.Entry("invalid address", "address", "", "invalid config Address: zero value"),
			table.Entry("invalid key", "private_key", "", "invalid config PrivateKey: zero value"),
			table.Entry("invalid cert", "certificate", "", "invalid config Certificate: zero value"),
		)

	})

})

func cloneMap(requiredFields map[string]string) map[string]string {
	configMap := map[string]string{}

	for key, value := range requiredFields {
		configMap[key] = value
	}

	return configMap
}

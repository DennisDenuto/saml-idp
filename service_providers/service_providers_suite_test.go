package service_providers_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestServiceProviders(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ServiceProviders Suite")
}

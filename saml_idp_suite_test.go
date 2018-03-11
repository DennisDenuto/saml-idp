package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestSamlIdp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SamlIdp Suite")
}

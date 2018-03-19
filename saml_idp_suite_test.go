package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
	"github.com/onsi/gomega/gexec"
	"time"
)

var pathToServer string

func TestSamlIdp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SamlIdp Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	path, err := gexec.Build("github.com/DennisDenuto/saml-idp")
	Expect(err).NotTo(HaveOccurred())
	SetDefaultEventuallyTimeout(2 * time.Second)
	return []byte(path)
}, func(data []byte) {
	pathToServer = string(data)
})


var _ = SynchronizedAfterSuite(func() {
}, func() {
	gexec.CleanupBuildArtifacts()
})

package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/gbytes"
	"os/exec"
	"net/http"
	"os"
	"github.com/DennisDenuto/saml-idp/config"
	"encoding/json"
	"io/ioutil"
	"github.com/cznic/fileutil"
	"github.com/crewjam/saml/samlidp"
	"crypto/tls"
)

var _ = Describe("Main", func() {
	var cmd *exec.Cmd
	var session *gexec.Session
	var serverStartMessage string
	var idpAddress string
	var idpCertificate string
	var idpKey string
	var idpConfig *config.Config
	var users []samlidp.User
	var usersTempFile *os.File
	var idpCertificateFile *os.File
	var idpPrivateKeyFile *os.File

	BeforeEach(func() {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		idpAddress = "https://localhost:9090"
		idpCertificate = string(LocalhostCert)
		idpKey = string(LocalhostKey)
		serverStartMessage = "Server Listening"
	})

	BeforeEach(func() {
		var password = "some-password"

		users = []samlidp.User{{
			"Bob", &password, []byte(""), []string{"group1"}, "bob@email.com", "BOB", "Bobby", "Bobbie",
		}}

		usersJson, err := json.Marshal(users)
		Expect(err).NotTo(HaveOccurred())

		usersTempFile, err = fileutil.TempFile(os.TempDir(), "users", "test")
		Expect(err).NotTo(HaveOccurred())
		err = ioutil.WriteFile(usersTempFile.Name(), usersJson, os.ModePerm)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if usersTempFile != nil {
			os.Remove(usersTempFile.Name())
		}

		if idpCertificateFile != nil {
			os.Remove(idpCertificateFile.Name())
		}

		if idpPrivateKeyFile != nil {
			os.Remove(idpPrivateKeyFile.Name())
		}

	})

	JustBeforeEach(func() {
		var err error
		idpCertificateFile, err = fileutil.TempFile(os.TempDir(), "idp", "test")
		Expect(err).NotTo(HaveOccurred())
		_, err = idpCertificateFile.WriteString(idpCertificate)
		Expect(err).NotTo(HaveOccurred())

		idpPrivateKeyFile, err = fileutil.TempFile(os.TempDir(), "idp", "test")
		Expect(err).NotTo(HaveOccurred())
		_, err = idpPrivateKeyFile.WriteString(idpKey)
		Expect(err).NotTo(HaveOccurred())

		idpConfig = &config.Config{
			Address:     idpAddress,
			Certificate: idpCertificateFile.Name(),
			PrivateKey:  idpPrivateKeyFile.Name(),
		}

		jsonString, err := json.Marshal(idpConfig)
		Expect(err).NotTo(HaveOccurred())

		tempFile, err := fileutil.TempFile(os.TempDir(), "config", "idp")
		Expect(err).NotTo(HaveOccurred())
		err = ioutil.WriteFile(tempFile.Name(), jsonString, os.ModePerm)
		Expect(err).NotTo(HaveOccurred())

		cmd = exec.Command(pathToServer, "-c", tempFile.Name(), "-users", usersTempFile.Name())

		session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(session).Should(gbytes.Say(serverStartMessage))
	})

	AfterEach(func() {
		session.Kill()
		Eventually(session).Should(gexec.Exit())
	})

	It("should start server with correct address", func() {
		request, err := http.NewRequest("GET", "https://localhost:9090/metadata", nil)
		Expect(err).NotTo(HaveOccurred())

		response, err := http.DefaultClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(200))

		println("hi")
		bytes, _ := ioutil.ReadAll(response.Body)
		println(string(bytes))
	})

	It("should stop server gracefully when interrupt signal is given", func() {
		session := session.Signal(os.Interrupt)
		Eventually(session).Should(gbytes.Say("Stopping Server"))
	})

	It("should be loaded with users from users file", func() {
		request, err := http.NewRequest("GET", "https://localhost:9090/users/Bob", nil)
		Expect(err).NotTo(HaveOccurred())

		response, err := http.DefaultClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(200))

		bytes, err := ioutil.ReadAll(response.Body)
		Expect(err).NotTo(HaveOccurred())
		storedUser := &samlidp.User{}
		json.Unmarshal(bytes, storedUser)
		Expect(storedUser.PlaintextPassword).To(BeNil())
		Expect(storedUser.Email).To(Equal("bob@email.com"))
	})

	Context("Given invalid listen address", func() {
		BeforeEach(func() {
			idpAddress = "httasd://invalidurl"
			serverStartMessage = "Cannot create tcp listener:listen tcp: address invalidurl: missing port in address"
		})

		It("should fail with an error message", func() {
			Eventually(session).Should(gexec.Exit())
			Eventually(session).ShouldNot(gexec.Exit(0))
		})
	})

	Context("Given invalid certs", func() {
		BeforeEach(func() {
			idpCertificate = "not-a-cert"
			serverStartMessage = "Cannot validate certificate:"
		})

		It("should fail with an error message", func() {
			Eventually(session).Should(gexec.Exit())
			Eventually(session).ShouldNot(gexec.Exit(0))
		})
	})

	Context("Given invalid key", func() {
		BeforeEach(func() {
			idpKey = "not-a-key"
			serverStartMessage = "Cannot validate private key:"
		})

		It("should fail with an error message", func() {
			Eventually(session).Should(gexec.Exit())
			Eventually(session).ShouldNot(gexec.Exit(0))
		})
	})
})

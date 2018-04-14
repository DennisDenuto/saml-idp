package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"net/url"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
	"github.com/zenazn/goji"
	"golang.org/x/crypto/bcrypt"
	"os"
	"os/signal"
	"net"
	"github.com/DennisDenuto/saml-idp/config"
	"io/ioutil"
	"errors"
	"encoding/json"
	"github.com/DennisDenuto/saml-idp/service_providers"
	"time"
	"crypto/tls"
	"log"
)

func main() {
	logr := logger.DefaultLogger
	configFile := flag.String("c", "", "The Path to the idp config file")
	usersFilePath := flag.String("users", "", "The Path to the users file")
	flag.Parse()

	configFileContents, err := ioutil.ReadFile(*configFile)
	if err != nil {
		panic(err)
	}
	idpConfig, err := config.NewConfig(configFileContents)
	if err != nil {
		panic(err)
	}

	cert, err := validateCert(idpConfig.Certificate)
	if err != nil {
		logr.Fatal("Cannot validate certificate:", err)
	}

	key, err := validateKey(idpConfig.PrivateKey)
	if err != nil {
		logr.Fatal("Cannot validate private key:", err)
	}

	store := &samlidp.MemoryStore{}

	baseURL, err := url.Parse(idpConfig.Address)
	if err != nil {
		logr.Fatalf("cannot parse base URL: %v", err)
	}
	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Logger:      logr,
		Certificate: cert,
		Store:       store,
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	err = addUsers(usersFilePath, idpServer.Store)
	if err != nil {
		logr.Fatalf("%s", err)
	}

	goji.Handle("/*", idpServer)

	tlsListener := createTLSListener(baseURL, logr, idpConfig)

	go func() {
		goji.ServeListener(tlsListener)
	}()

	logr.Print("Server Listening")

	bootstrap := service_providers.SPBootstrap{
		MetadataURLs: idpConfig.ServiceProviderMetadataURLs,
		Timeout:      3 * time.Minute,
		SpMetadataConfigurer: service_providers.SPMetadataConfigurerStore{
			Store: store,
		},
		Logger: logr,
	}
	err = bootstrap.Run()
	if err != nil {
		logr.Fatal("Cannot bootstrap SPs:", err)
	}

	interruptSignal := make(chan os.Signal, 1)
	signal.Notify(interruptSignal)

	select {
	case <-interruptSignal:
		logr.Print("Stopping Server")
	}
}

func createTLSListener(baseURL *url.URL, logr *log.Logger, idpConfig *config.Config) net.Listener {
	l, err := net.Listen("tcp", baseURL.Host)
	if err != nil {
		logr.Fatal("Cannot create tcp listener:", err)

	}
	serverCert, err := tls.LoadX509KeyPair(idpConfig.Certificate, idpConfig.PrivateKey)
	if err != nil {
		logr.Fatal("Unable to load server cert", err)
	}
	tlsListener := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	})
	if err != nil {
		logr.Fatal("Cannot create tls listener:", err)
	}
	return tlsListener
}

func addUsers(usersFilePath *string, store samlidp.Store) error {
	usersFileContent, err := ioutil.ReadFile(*usersFilePath)
	if err != nil {
		return err
	}
	usersToAdd := &[]samlidp.User{}
	err = json.Unmarshal(usersFileContent, usersToAdd)
	if err != nil {
		return err
	}
	for _, user := range *usersToAdd {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(*user.PlaintextPassword), bcrypt.DefaultCost)
		user.HashedPassword = hashedPassword
		user.PlaintextPassword = nil
		err = store.Put("/users/"+user.Name, user)
		if err != nil {
			return err
		}
	}
	return nil
}

func validateCert(certPath string) (*x509.Certificate, error) {
	certificate, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode([]byte(certificate))
	if b == nil {
		return nil, errors.New("no pem block found")
	}
	return x509.ParseCertificate(b.Bytes)
}

func validateKey(keyPath string) (crypto.PrivateKey, error) {
	privateKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode([]byte(privateKey))
	if b == nil {
		return nil, errors.New("no pem block found")
	}
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}

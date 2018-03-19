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
)

func main() {
	logr := logger.DefaultLogger
	configFile := flag.String("c", "", "The Path to the idp config file")
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

	baseURL, err := url.Parse(idpConfig.Address)
	if err != nil {
		logr.Fatalf("cannot parse base URL: %v", err)
	}
	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Logger:      logr,
		Certificate: cert,
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	err = idpServer.Store.Put("/users/alice", samlidp.User{Name: "alice",
		HashedPassword: hashedPassword,
		Groups: []string{"Administrators", "Users"},
		Email: "alice@example.com",
		CommonName: "Alice Smith",
		Surname: "Smith",
		GivenName: "Alice",
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	err = idpServer.Store.Put("/users/bob", samlidp.User{
		Name:           "bob",
		HashedPassword: hashedPassword,
		Groups:         []string{"Users"},
		Email:          "bob@example.com",
		CommonName:     "Bob Smith",
		Surname:        "Smith",
		GivenName:      "Bob",
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	goji.Handle("/*", idpServer)
	l, err := net.Listen("tcp", baseURL.Host)
	if err != nil {
		logr.Fatal("Server Error:", err)

	}
	go func() {
		goji.ServeListener(l)
	}()

	logr.Print("Server Listening")

	interruptSignal := make(chan os.Signal, 1)
	signal.Notify(interruptSignal)

	select {
	case <-interruptSignal:
		logr.Print("Stopping Server")
	}
}

func validateCert(cert string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(cert))
	if b == nil {
		return nil, errors.New("no pem block found")
	}
	return x509.ParseCertificate(b.Bytes)
}

func validateKey(key string) (crypto.PrivateKey, error) {
	b, _ := pem.Decode([]byte(key))
	if b == nil {
		return nil, errors.New("no pem block found")
	}
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}

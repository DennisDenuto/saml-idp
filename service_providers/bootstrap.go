package service_providers

import (
	"net/http"
	"fmt"
	"github.com/pkg/errors"
	"github.com/crewjam/saml/logger"
	"time"
	"sync"
	"crypto/tls"
	"github.com/crewjam/saml/samlidp"
)

//go:generate counterfeiter . Store
type Store interface {
	Put(key string, value interface{}) error
}

type SPBootstrap struct {
	MetadataURLs         map[string]string
	Timeout              time.Duration
	SpMetadataConfigurer SPMetadataConfigurer
	BackOffDuration      time.Duration
	Logger               logger.Interface
}

func (s SPBootstrap) Run() error {
	var wg = &sync.WaitGroup{}
	var errChan = make(chan error, len(s.MetadataURLs))
	for spName, metadataUrl := range s.MetadataURLs {
		wg.Add(1)
		go func(spName string, metadataUrl string) {
			defer wg.Done()
			AddSPFunc := s.SpMetadataConfigurer.AddSP
			backOffFunc := BackOff(s.Logger, s.BackOffDuration, AddSPFunc)
			err := AddSPRetrier(s.Logger, backOffFunc)(spName, metadataUrl)
			if err != nil {
				errChan <- err
			}
		}(spName, metadataUrl)
	}
	go func() {
		wg.Wait()
		close(errChan)
	}()

	timeout := time.After(s.Timeout)
	for {
		select {
		case err := <-errChan:
			return err
		case <-timeout:
			return errors.New("timedout waiting for SP metadata")
		}
	}
	return nil
}

func BackOff(logger logger.Interface, backOffDuration time.Duration, f func(string, string) error) AddSPFunc {
	return AddSPFunc(func(spID string, url string) error {
		err := f(spID, url)
		if err == nil {
			return nil
		}
		logger.Printf("Backing off. Sleeping for %v", backOffDuration)
		time.Sleep(backOffDuration)
		return err
	})
}

func AddSPRetrier(logger logger.Interface, f AddSPFunc) AddSPFunc {
	return AddSPFunc(func(spId string, url string) error {
		var err error
		for numRetries := 0; numRetries < 3; numRetries++ {
			logger.Printf("Trying %s metatadata url: (%s) call attempt: %d", spId, url, numRetries)
			err = f(spId, url)
			if err == nil {
				return nil
			}
		}
		return errors.Wrap(err, "Failed Adding SP after 3 retries")
	})

}

type AddSPFunc func(string, string) error

//go:generate counterfeiter . SPMetadataConfigurer
type SPMetadataConfigurer interface {
	AddSP(string, string) error
}

type SPMetadataConfigurerStore struct {
	Store Store
}

func (s SPMetadataConfigurerStore) AddSP(spId string, metadataURL string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	response, err := client.Get(metadataURL)
	if err != nil {
		return errors.Wrap(err, "AddSP Unable to get metadata xml")
	}
	defer response.Body.Close()

	service := samlidp.Service{}

	metadata, err := GetSPMetadata(response.Body)
	if err != nil {
		return errors.Wrap(err, "AddSP could not retrieve SP metadata")
	}
	service.Metadata = *metadata

	return s.Store.Put(fmt.Sprintf("/services/%s", spId), &service)
}

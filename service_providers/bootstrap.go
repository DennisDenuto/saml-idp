package service_providers

import (
	"net/http"
	"net/url"
	"io/ioutil"
	"encoding/xml"
	"fmt"
	"github.com/pkg/errors"
	"github.com/crewjam/saml/logger"
	"time"
	"sync"
)

//go:generate counterfeiter . Store
type Store interface {
	Put(key string, value interface{}) error
}

type SPBootstrap struct {
	MetadataURLs         []string
	Timeout              time.Duration
	SpMetadataConfigurer SPMetadataConfigurer
	Logger               logger.Interface
}

func (s SPBootstrap) Run() error {
	var wg = &sync.WaitGroup{}
	var errChan = make(chan error, len(s.MetadataURLs))
	for _, metadataUrl := range s.MetadataURLs {
		wg.Add(1)
		go func(metadataUrl string) {
			defer wg.Done()
			err := AddSPRetrier(s.Logger, s.SpMetadataConfigurer.AddSP)(metadataUrl)
			if err != nil {
				errChan <- err
			}
		}(metadataUrl)
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

func AddSPRetrier(logger logger.Interface, f AddSPFunc) AddSPFunc {
	return AddSPFunc(func(url string) error {
		var err error
		for numRetries := 0; numRetries < 3; numRetries++ {
			logger.Printf("Trying metatadata url: (%s) call attempt: %d", url, numRetries)
			err = f(url)
			if err == nil {
				return nil
			}
		}
		return errors.Wrap(err, "Failed Adding SP after 3 retries")
	})

}

type AddSPFunc func(string) error

//go:generate counterfeiter . SPMetadataConfigurer
type SPMetadataConfigurer interface {
	AddSP(string) error
}

type SPMetadataConfigurerStore struct {
	Store Store
}

func (s SPMetadataConfigurerStore) AddSP(metadataURL string) error {
	client := http.DefaultClient
	parsedUrl, err := url.Parse(metadataURL)
	if err != nil {
		return errors.Wrap(err, "AddSP Unable to parse metadata url")
	}

	response, err := client.Get(metadataURL)
	if err != nil {
		return errors.Wrap(err, "AddSP Unable to get metadata xml")
	}
	defer response.Body.Close()

	spXmlMetadata, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errors.Wrap(err, "AddSP Unable to read metadata response")
	}

	var data interface{}
	err = xml.Unmarshal(spXmlMetadata, &data)
	if err != nil {
		return errors.Wrap(err, "AddSP metatadata response is not xml")
	}

	return s.Store.Put(
		fmt.Sprintf("/services/%s", parsedUrl.Hostname()),
		string(spXmlMetadata),
	)
}

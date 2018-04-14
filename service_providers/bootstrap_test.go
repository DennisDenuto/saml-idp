package service_providers_test

import (
	. "github.com/DennisDenuto/saml-idp/service_providers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/DennisDenuto/saml-idp/service_providers/service_providersfakes"
	"github.com/onsi/gomega/ghttp"
	"fmt"
	"github.com/crewjam/saml/logger"
	"time"
	"net/http"
)

var _ = Describe("Bootstrap", func() {
	var bootstrap SPBootstrap
	var store *service_providersfakes.FakeStore
	var server *ghttp.Server

	BeforeEach(func() {
		server = ghttp.NewServer()
		server.UnhandledRequestStatusCode = 500

		store = &service_providersfakes.FakeStore{}
		bootstrap = SPBootstrap{
			Logger: logger.DefaultLogger,
			SpMetadataConfigurer: SPMetadataConfigurerStore{
				Store: store,
			},
			MetadataURLs: map[string]string{
				"sp_id": fmt.Sprintf("%s/metadata", server.URL()),
			},
			Timeout: 3 * time.Second,
		}
	})

	AfterEach(func() {
		server.Close()
	})

	Context("when given a valid sp metadataurl", func() {
		BeforeEach(func() {
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/metadata"),
					ghttp.RespondWith(200, "<xml></xml>"),
				),
			)
		})

		It("should populate sp store with configured sps", func() {
			err := bootstrap.Run()
			Expect(err).NotTo(HaveOccurred())

			Expect(server.ReceivedRequests()).To(HaveLen(1))
			Expect(store.PutCallCount()).To(Equal(1))
			key, value := store.PutArgsForCall(0)
			Expect(key).To(Equal(fmt.Sprintf("/services/%s", "sp_id")))
			Expect(value).To(Equal("<xml></xml>"))
		})

		Context("when sp metadata service is initially unavailable but eventually comes back up", func() {
			BeforeEach(func() {
				server.SetHandler(0, ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/metadata"),
					ghttp.RespondWith(503, "error"),
				),
				)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/metadata"),
						ghttp.RespondWith(200, "<xml></xml>"),
					),
				)
			})

			It("should populate sp store with configured sps", func() {
				err := bootstrap.Run()
				Expect(err).NotTo(HaveOccurred())

				Expect(server.ReceivedRequests()).To(HaveLen(2))
				Expect(store.PutCallCount()).To(Equal(1))
				key, value := store.PutArgsForCall(0)
				Expect(key).To(Equal(fmt.Sprintf("/services/%s", "sp_id")))
				Expect(value).To(Equal("<xml></xml>"))
			})
		})
	})

	Context("when given sp metadataurl does not return valid xml", func() {
		BeforeEach(func() {
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/metadata"),
					ghttp.RespondWith(200, "not valid xml"),
				),
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/metadata"),
					ghttp.RespondWith(200, "not valid xml"),
				),
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/metadata"),
					ghttp.RespondWith(200, "not valid xml"),
				),
			)
		})

		It("should return an error", func() {
			err := bootstrap.Run()
			Expect(err).To(HaveOccurred())

			Expect(server.ReceivedRequests()).To(HaveLen(3))
			Expect(store.PutCallCount()).To(Equal(0))
		})
	})

	Context("when given sp metadataurl that takes too long", func() {
		var configurer *service_providersfakes.FakeSPMetadataConfigurer

		BeforeEach(func() {
			configurer = &service_providersfakes.FakeSPMetadataConfigurer{}
			configurer.AddSPStub = func(string, string) error {
				time.Sleep(10 * time.Minute)
				return nil
			}

			bootstrap.Timeout = 1
			bootstrap.SpMetadataConfigurer = configurer
		})

		It("should timeout with an error", func() {
			errChan := make(chan error)
			Eventually(func() chan error {
				go func(chan error) {
					errChan <- bootstrap.Run()
				}(errChan)
				return errChan
			}, 5, 1).Should(Receive(HaveOccurred()))
		})
	})

	Context("when given multiple sp metadataurl", func() {
		BeforeEach(func() {
			bootstrap.MetadataURLs = map[string]string{
				"sp_id1": fmt.Sprintf("%s/metadata", server.URL()),
				"sp_id2": fmt.Sprintf("%s/metadata", server.URL()),
			}
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/metadata"),
					ghttp.RespondWith(200, "<xml></xml>"),
				),
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/metadata"),
					ghttp.RespondWith(200, "<xml></xml>"),
				),
			)
		})

		It("should populate sp store with configured sps", func() {
			err := bootstrap.Run()
			Expect(err).NotTo(HaveOccurred())

			Expect(server.ReceivedRequests()).To(HaveLen(2))
			Expect(store.PutCallCount()).To(Equal(2))
			key, value := store.PutArgsForCall(0)
			Expect(key).To(Equal(fmt.Sprintf("/services/%s", "sp_id1")))
			Expect(value).To(Equal("<xml></xml>"))

			key, value = store.PutArgsForCall(1)
			Expect(key).To(Equal(fmt.Sprintf("/services/%s", "sp_id2")))
			Expect(value).To(Equal("<xml></xml>"))
		})

	})

	Context("when second SP metadata fails", func() {
		BeforeEach(func() {
			bootstrap.MetadataURLs = map[string]string{
				"sp_id1": fmt.Sprintf("%s/metadata", server.URL()),
				"sp_id2": fmt.Sprintf("%s/metadata_with_err", server.URL()),
			}

			server.RouteToHandler("GET", "/metadata", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("<xml></xml>"))
			})

			server.RouteToHandler("GET", "/metadata_with_err", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("not valid xml"))
			})
		})

		It("should return an error", func() {
			err := bootstrap.Run()
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("Failed Adding SP after 3 retries: AddSP metatadata response is not xml: EOF"))
		})

	})

})

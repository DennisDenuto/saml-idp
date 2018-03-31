package service_providers_test

import (
	. "github.com/DennisDenuto/saml-idp/service_providers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/DennisDenuto/saml-idp/service_providers/service_providersfakes"
	"github.com/onsi/gomega/ghttp"
	"fmt"
	"github.com/crewjam/saml/logger"
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
			MetadataURLs: []string{
				fmt.Sprintf("%s/metadata", server.URL()),
			},
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
			Expect(key).To(Equal(fmt.Sprintf("/services/%s", "127.0.0.1")))
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
				Expect(key).To(Equal(fmt.Sprintf("/services/%s", "127.0.0.1")))
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
})

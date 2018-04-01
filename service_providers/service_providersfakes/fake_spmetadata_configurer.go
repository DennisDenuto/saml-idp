// This file was generated by counterfeiter
package service_providersfakes

import (
	"sync"

	"github.com/DennisDenuto/saml-idp/service_providers"
)

type FakeSPMetadataConfigurer struct {
	AddSPStub        func(string) error
	addSPMutex       sync.RWMutex
	addSPArgsForCall []struct {
		arg1 string
	}
	addSPReturns struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeSPMetadataConfigurer) AddSP(arg1 string) error {
	fake.addSPMutex.Lock()
	fake.addSPArgsForCall = append(fake.addSPArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("AddSP", []interface{}{arg1})
	fake.addSPMutex.Unlock()
	if fake.AddSPStub != nil {
		return fake.AddSPStub(arg1)
	} else {
		return fake.addSPReturns.result1
	}
}

func (fake *FakeSPMetadataConfigurer) AddSPCallCount() int {
	fake.addSPMutex.RLock()
	defer fake.addSPMutex.RUnlock()
	return len(fake.addSPArgsForCall)
}

func (fake *FakeSPMetadataConfigurer) AddSPArgsForCall(i int) string {
	fake.addSPMutex.RLock()
	defer fake.addSPMutex.RUnlock()
	return fake.addSPArgsForCall[i].arg1
}

func (fake *FakeSPMetadataConfigurer) AddSPReturns(result1 error) {
	fake.AddSPStub = nil
	fake.addSPReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeSPMetadataConfigurer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.addSPMutex.RLock()
	defer fake.addSPMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeSPMetadataConfigurer) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ service_providers.SPMetadataConfigurer = new(FakeSPMetadataConfigurer)
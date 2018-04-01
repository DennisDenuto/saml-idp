// This file was generated by counterfeiter
package service_providersfakes

import (
	"sync"

	"github.com/DennisDenuto/saml-idp/service_providers"
)

type FakeStore struct {
	PutStub        func(key string, value interface{}) error
	putMutex       sync.RWMutex
	putArgsForCall []struct {
		key   string
		value interface{}
	}
	putReturns struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeStore) Put(key string, value interface{}) error {
	fake.putMutex.Lock()
	fake.putArgsForCall = append(fake.putArgsForCall, struct {
		key   string
		value interface{}
	}{key, value})
	fake.recordInvocation("Put", []interface{}{key, value})
	fake.putMutex.Unlock()
	if fake.PutStub != nil {
		return fake.PutStub(key, value)
	} else {
		return fake.putReturns.result1
	}
}

func (fake *FakeStore) PutCallCount() int {
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	return len(fake.putArgsForCall)
}

func (fake *FakeStore) PutArgsForCall(i int) (string, interface{}) {
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	return fake.putArgsForCall[i].key, fake.putArgsForCall[i].value
}

func (fake *FakeStore) PutReturns(result1 error) {
	fake.PutStub = nil
	fake.putReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeStore) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeStore) recordInvocation(key string, args []interface{}) {
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

var _ service_providers.Store = new(FakeStore)
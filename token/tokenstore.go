package token

import (
	"fmt"
	"sync"
	"time"
)

const defaultInitialCapacity = 1024

func NewTokenStore(ttl time.Duration, initialCapacity int) Store {
	if initialCapacity <= 0 {
		initialCapacity = defaultInitialCapacity
	}
	mu := sync.Mutex{}
	syncedMapStore := syncedMapStore{mapStore{}, &mu}
	factory := newTokenRingFactory(initialCapacity)
	curr := factory.manufacture()
	return &TokenStore{syncedMapStore, ttl, curr, factory}
}

type TokenStore struct {
	syncedMapStore
	ttl              time.Duration
	curr             *tokenRing
	tokenRingFactory *tokenRingFactory
}

func (mem *TokenStore) Store(payload interface{}) (string, error) {
	envelope := envelope{payload, time.Now(), mem.ttl}
	return mem.store(&envelope)
}

func (mem *TokenStore) Fetch(token string) (interface{}, error) {
	envelopeProbe, err := mem.syncedMapStore.Fetch(token)
	if err != nil {
		return nil, err
	}
	envelope, ok := envelopeProbe.(envelope)
	if !ok {
		return nil, fmt.Errorf("wrong type fetched")
	}
	if envelope.expired() {
		return envelope.payload, fmt.Errorf("token expired: %v", token)
	}
	return envelope.payload, nil
}

func (mem *TokenStore) Enum(callback func(string, interface{}, bool, time.Duration)) {
	mem.mu.Lock()
	defer mem.mu.Unlock()
	for token, envelopeProbe := range mem.mapstore {
		envelope, _ := envelopeProbe.(envelope)
		callback(token, envelope.payload, !envelope.expired(), time.Since(envelope.created.Add(envelope.ttl)))
	}
}

func (mem *TokenStore) store(envelope *envelope) (string, error) {
	token, err := mem.syncedMapStore.Store(*envelope)
	if err != nil {
		return "", err
	}
	entry := entry{token, envelope}
	storeAndBudge := func() {
		mem.curr.entry = &entry
		mem.curr = mem.curr.next
	}
	mem.mu.Lock()
	defer mem.mu.Unlock()
	if e := mem.curr.entry; e == nil {
		storeAndBudge()
		return token, nil
	}
	if e := mem.curr.entry.envelope; e.expired() {
		delete(mem.mapstore, mem.curr.entry.token)
		storeAndBudge()
		return token, nil
	}
	mem.expandTokenRing()
	storeAndBudge()
	return token, nil
}

type envelope struct {
	payload interface{}
	created time.Time
	ttl     time.Duration
}

func (e *envelope) expired() bool {
	return e.created.Add(e.ttl).Before(time.Now())
}

type entry struct {
	token    string
	envelope *envelope
}

type tokenRing struct {
	prev  *tokenRing
	next  *tokenRing
	entry *entry
}

func (mem *TokenStore) expandTokenRing() {
	first := mem.tokenRingFactory.manufacture()
	first.prev.next = mem.curr.next
	mem.curr.next = first
	mem.curr = mem.curr.next
}

type tokenRingFactory struct {
	initialCapacity int
	demandCounter   int
	spareChannel    chan *tokenRing
}

func newTokenRingFactory(initialCapacity int) *tokenRingFactory {
	ch := make(chan *tokenRing, 2)
	return &tokenRingFactory{initialCapacity: initialCapacity, spareChannel: ch, demandCounter: -1}
}

func (fct *tokenRingFactory) manufacture() *tokenRing {
	makeNew := func() {

		first := &tokenRing{}
		last := first
		capacity := pow2(fct.demandCounter) * fct.initialCapacity
		for i := 0; i < capacity-1; i++ {
			last.next = &tokenRing{last, nil, nil}
			last = last.next
		}
		last.next = first
		first.prev = last
		fct.demandCounter++
		fct.spareChannel <- first
	}
	if fct.demandCounter < 0 {
		makeNew()
	}
	go makeNew()
	return <-fct.spareChannel
}

func pow2(y int) int {
	if y <= 0 {
		return 1
	}
	return 2 * pow2(y-1)
}

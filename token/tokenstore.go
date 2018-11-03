package token

import (
	"fmt"
	"sync"
	"time"
)

const defaultInitialCapacity = 1024

func NewTokenStore(ttl time.Duration, initialCapacity int) Store {
	if initialCapacity <= 1 {
		initialCapacity = defaultInitialCapacity
	}
	mu := sync.RWMutex{}
	syncedMapStore := syncedMapStore{mapStore{}, &mu}
	factory := newTokenRingFactory(initialCapacity)
	prev := factory.manufacture()
	curr := prev.next
	return &TokenStore{syncedMapStore, ttl, curr, prev, factory}
}

type TokenStore struct {
	syncedMapStore
	ttl              time.Duration
	curr             *tokenRing
	prev             *tokenRing
	tokenRingFactory *tokenRingFactory
}

func (ts *TokenStore) Store(payload interface{}) (string, error) {
	envelope := envelope{payload, time.Now(), ts.ttl}
	return ts.store(&envelope)
}

func (ts *TokenStore) Fetch(token string) (interface{}, error) {
	envelopeProbe, err := ts.syncedMapStore.Fetch(token)
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

func (ts *TokenStore) Enum(callback func(string, interface{}, bool, time.Duration)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for token, envelopeProbe := range ts.mapstore {
		envelope, _ := envelopeProbe.(envelope)
		callback(token, envelope.payload, !envelope.expired(), time.Since(envelope.created.Add(envelope.ttl)))
	}
}

func (ts *TokenStore) store(envelope *envelope) (string, error) {
	token, err := ts.syncedMapStore.Store(*envelope)
	if err != nil {
		return "", err
	}
	entry := entry{token, envelope}
	storeAndBudge := func() {
		ts.curr.entry = &entry
		ts.prev = ts.curr
		ts.curr = ts.curr.next
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if e := ts.curr.entry; e == nil {
		storeAndBudge()
		return token, nil
	}
	if e := ts.curr.entry.envelope; e.expired() {
		delete(ts.mapstore, ts.curr.entry.token)
		storeAndBudge()
		return token, nil
	}
	ts.expandTokenRing()
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
	next  *tokenRing
	entry *entry
}

func (ts *TokenStore) expandTokenRing() {
	last := ts.tokenRingFactory.manufacture()
	first := last.next
	last.next = ts.curr
	ts.prev.next = first
	ts.curr = first
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
			last.next = &tokenRing{last, nil}
			last = last.next
		}
		last.next = first
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

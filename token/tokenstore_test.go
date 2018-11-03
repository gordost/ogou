package token

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

const ttl = time.Duration(500 * time.Millisecond)
const initialCapacity = 5

const unexpectedRingCapacity = "unexpected ring capacity: expected %v, got %v"
const unexpectedCountOfValidEntries = "unexpected count of valid entries: expected %v, got %v"
const unexpectedLengthOfEntryMap = "unexpected length of the entry map: expected %v, got %v"

func TestRingFactory(t *testing.T) {
	factory := newTokenRingFactory(initialCapacity)
	ring := factory.manufacture()
	checkCount(t, ring, nil, initialCapacity, unexpectedRingCapacity)
	ring = factory.manufacture()
	checkCount(t, ring, nil, initialCapacity, unexpectedRingCapacity)
	ring = factory.manufacture()
	checkCount(t, ring, nil, 2*initialCapacity, unexpectedRingCapacity)
	ring = factory.manufacture()
	checkCount(t, ring, nil, 4*initialCapacity, unexpectedRingCapacity)
	ring = factory.manufacture()
	checkCount(t, ring, nil, 8*initialCapacity, unexpectedRingCapacity)
	ring = factory.manufacture()
	checkCount(t, ring, nil, 16*initialCapacity, unexpectedRingCapacity)
}

func TestTokenStoreFetch(t *testing.T) {
	store := NewTokenStore(ttl, initialCapacity)
	tokenStore, _ := store.(*TokenStore)
	var token string
	var err error
	for i := 0; i < initialCapacity; i++ {
		token, err = store.Store("something" + string(i))
		if err != nil {
			t.Fatal(err)
		}
	}
	checkCount(t, tokenStore.curr, filterValid, initialCapacity, unexpectedCountOfValidEntries)
	checkCount(t, tokenStore.curr, nil, initialCapacity, unexpectedRingCapacity)
	time.Sleep(ttl)
	expiredProbe, err := store.Fetch(token)
	if err == nil {
		t.Fatal(fmt.Errorf("unexpectedly got valid token: %v:%v", token, expiredProbe))
	}
	if expiredProbe == nil {
		t.Fatal(fmt.Errorf("unexpectedly got nil payload for token %v", token))
	}
	expired := expiredProbe.(string)
	if expired != "something"+string(initialCapacity-1) {
		t.Fatal(fmt.Errorf("got unexpected payload: %v:%v", token, expired))
	}
	key, err := store.Store("another")
	if err != nil {
		t.Fatal(err)
	}
	checkCount(t, tokenStore.curr, nil, initialCapacity, unexpectedRingCapacity)
	something, err := store.Fetch(key)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := something.(string)
	if !ok {
		t.Fatal("unexpected type of stored object")
	}
	if s != "another" {
		t.Fatal("unexpected stored object returned")
	}
	if len(tokenStore.mapstore) != initialCapacity {
		t.Fatalf(unexpectedLengthOfEntryMap, initialCapacity, len(tokenStore.mapstore))
	}
	checkCount(t, tokenStore.curr, filterValid, 1, unexpectedCountOfValidEntries)
	for i := 0; i < initialCapacity; i++ {
		token, err = store.Store("somethingelse" + string(i))
		if err != nil {
			t.Fatal(err)
		}
	}
	checkCount(t, tokenStore.curr, filterValid, initialCapacity+1, unexpectedCountOfValidEntries)
	checkCount(t, tokenStore.curr, nil, 2*initialCapacity, unexpectedRingCapacity)
}

func TestTokenStoreConcurrency(t *testing.T) {
	var concurrencyTests = []struct {
		volume             int
		expectedRingLength int
	}{
		{10, 10},
		{11, 20},
		{20, 20},
		{21, 40},
		{39, 40},
		{40, 40},
		{41, 80},
		{80, 80},
		{81, 160},
		{100, 160},
		{161, 320},
		{321, 640},
		{640, 640},
		{641, 1280},
		{1281, 2 * 1280},
		{2 * 1281, 4 * 1280},
	}
	for i := 0; i < len(concurrencyTests); i++ {
		testTokenStoreConcurrency(t, concurrencyTests[i].volume, concurrencyTests[i].expectedRingLength)
	}
}

func testTokenStoreConcurrency(t *testing.T, volume int, expected int) {
	store := NewTokenStore(ttl, initialCapacity)
	mem, _ := store.(*TokenStore)
	var wg sync.WaitGroup
	storeWrapper := func(wg *sync.WaitGroup) {
		defer wg.Done()
		random, _ := random()
		store.Store(random)
	}
	fetchWrapper := func(wg *sync.WaitGroup) {
		defer wg.Done()
		random, _ := random()
		store.Fetch(random)
	}
	start := time.Now()
	for i := 0; i < volume; i++ {
		wg.Add(1)
		go storeWrapper(&wg)
		wg.Add(1)
		go fetchWrapper(&wg)
	}
	ok := isDoneWithinTimeout(&wg, ttl)
	if !ok {
		t.Fatal("no all go routines finished within timeout")
	}
	checkCount(t, mem.curr, nil, expected, unexpectedRingCapacity)
	t.Logf("Stress test elapsed time: %v", time.Since(start))
}

func filterValid(tr *tokenRing) bool {
	if tr.entry == nil {
		return false
	}
	return !tr.entry.envelope.expired()
}

func checkCount(t *testing.T, ring *tokenRing, filter func(tr *tokenRing) bool, expected int, msg string) {
	if l := ring.count(filter); l != expected {
		t.Fatalf(msg, expected, l)
	}
}

func (r *tokenRing) count(filter func(tr *tokenRing) bool) int {
	curr, l := r, 0
	for curr.next != r {
		if filter == nil || filter(curr.next) {
			l++
		}
		curr = curr.next
	}
	if filter == nil || filter(curr.next) {
		l++
	}
	return l
}

func isDoneWithinTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true
	case <-time.After(timeout):
		return false
	}
}

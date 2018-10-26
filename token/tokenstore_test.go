package token

import (
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

func TestTokenStore(t *testing.T) {
	testTokenStore(t, initialCapacity)
}

func TestTokenStoreStoreFetch(t *testing.T) {
	store := NewTokenStore(ttl, initialCapacity)
	mem, _ := store.(*TokenStore)
	for i := 0; i < initialCapacity; i++ {
		_, _ = mem.Store("something" + string(i))
	}
	time.Sleep(ttl)
	key, err := mem.Store("another")
	if err != nil {
		t.Fatal(err)
	}
	something, err := mem.Fetch(key)
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
	if len(mem.mapstore) != initialCapacity {
		t.Fatalf(unexpectedLengthOfEntryMap, initialCapacity, len(mem.mapstore))
	}
	checkCount(t, mem.curr, filterValid, 1, unexpectedCountOfValidEntries)
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
	testArr := make([]string, volume)
	var err error
	for i := 0; i < volume; i++ {
		testArr[i], err = random()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	var wg sync.WaitGroup
	storeWrapper := func(wg *sync.WaitGroup, key string) {
		defer wg.Done()
		store.Store(key)
	}
	fetchWrapper := func(wg *sync.WaitGroup, key string) {
		defer wg.Done()
		store.Fetch(key)
	}
	start := time.Now()
	for i := 0; i < volume; i++ {
		wg.Add(1)
		go storeWrapper(&wg, testArr[i])
		wg.Add(1)
		go fetchWrapper(&wg, testArr[i])
	}
	ok := isDoneWithinTimeout(&wg, ttl)
	if !ok {
		t.Fatal("no all go routines finished within timeout")
	}
	checkCount(t, mem.curr, nil, expected, unexpectedRingCapacity)
	t.Logf("Stress test elapsed time: %v", time.Since(start))
}

func testTokenStore(t *testing.T, capacity int) {
	store := NewTokenStore(ttl, capacity)
	mem, _ := store.(*TokenStore)
	checkCount(t, mem.curr, nil, capacity, unexpectedRingCapacity)

	for i := 0; i < capacity; i++ {
		store.Store("pay" + string(i))
	}

	checkCount(t, mem.curr, nil, capacity, unexpectedRingCapacity)
	checkCount(t, mem.curr, filterValid, capacity, unexpectedCountOfValidEntries)

	store.Store("newguy")
	checkCount(t, mem.curr, nil, 2*capacity, unexpectedRingCapacity)
	checkCount(t, mem.curr, filterValid, capacity+1, unexpectedCountOfValidEntries)
	if len(mem.mapstore) != capacity+1 {
		t.Fatalf(unexpectedLengthOfEntryMap, capacity+1, len(mem.mapstore))
	}

	time.Sleep(ttl)
	checkCount(t, mem.curr, nil, 2*capacity, unexpectedRingCapacity)
	checkCount(t, mem.curr, filterValid, 0, unexpectedCountOfValidEntries)
	for i := 0; i < capacity+1; i++ {
		store.Store("pay" + string(10000+i))
	}
	checkCount(t, mem.curr, nil, 2*capacity, unexpectedRingCapacity)
	checkCount(t, mem.curr, filterValid, capacity+1, unexpectedCountOfValidEntries)

	store.Store("newguy2")
	if len(mem.mapstore) != 2*capacity {
		t.Fatalf(unexpectedLengthOfEntryMap, 2*capacity, len(mem.mapstore))
	}

	for i := 0; i < 3*capacity+1; i++ {
		store.Store("pay" + string(10000+i))
	}
	checkCount(t, mem.curr, nil, 8*capacity, unexpectedRingCapacity)
	checkCount(t, mem.curr, filterValid, 4*capacity+2+1, unexpectedCountOfValidEntries)
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

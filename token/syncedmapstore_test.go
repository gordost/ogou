package token

import (
	"testing"
	"time"
)

var syncedmapstore = NewSyncedMapStore()

func TestSyncedMapStore(t *testing.T) {
	for i := 0; i < 100; i++ {
		go testStoreFetch(t, syncedmapstore)
	}
	time.Sleep(100 * time.Millisecond)
}

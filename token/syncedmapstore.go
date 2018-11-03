package token

import "sync"

func NewSyncedMapStore() Store {
	mu := sync.RWMutex{}
	return syncedMapStore{mapstore: mapStore{}, mu: &mu}
}

type syncedMapStore struct {
	mapstore mapStore
	mu       *sync.RWMutex
}

func (sms syncedMapStore) Store(payload interface{}) (string, error) {
	sms.mu.Lock()
	defer sms.mu.Unlock()
	return sms.mapstore.Store(payload)
}

func (sms syncedMapStore) Fetch(token string) (interface{}, error) {
	sms.mu.RLock()
	defer sms.mu.RUnlock()
	return sms.mapstore.Fetch(token)
}

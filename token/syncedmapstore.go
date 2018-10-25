package token

import "sync"

func NewSyncedMapStore() Store {
	mu := sync.Mutex{}
	return syncedMapStore{mapstore: mapStore{}, mu: &mu}
}

type syncedMapStore struct {
	mapstore mapStore
	mu       *sync.Mutex
}

func (sms syncedMapStore) Store(payload interface{}) (string, error) {
	sms.mu.Lock()
	defer sms.mu.Unlock()
	return sms.mapstore.Store(payload)
}

func (sms syncedMapStore) Fetch(token string) (interface{}, error) {
	sms.mu.Lock()
	defer sms.mu.Unlock()
	return sms.mapstore.Fetch(token)
}

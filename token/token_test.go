package token

import (
	"testing"
)

const samplePayload = "something"
const notAToken = "notAToken"

func testStoreFetch(t *testing.T, store Store) {

	token, err := store.Store(samplePayload)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := store.Fetch(token)
	if err != nil {
		t.Fatal(err)
	}

	if payload != samplePayload {
		t.Fatalf("not same: expected %v, got %v", samplePayload, payload)
	}

	payload, err = store.Fetch(notAToken)
	if err == nil {
		t.Fatalf("error expected, but got none (token: %v, payload %v)", notAToken, payload)
	}
}

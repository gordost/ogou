package token

import (
	"testing"
)

var mapstore = NewMapStore()

func TestMapStoreFetch(t *testing.T) {
	testStoreFetch(t, mapstore)
}

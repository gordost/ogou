package token

import (
	"crypto/rand"
	"fmt"
)

type mapStore map[string]interface{}

func NewMapStore() Store {
	return mapStore(make(map[string]interface{}))
}

func (ms mapStore) Store(payload interface{}) (string, error) {
	token, err := random()
	if err != nil {
		return "", err
	}
	ms[token] = payload
	return token, nil
}

func (ms mapStore) Fetch(token string) (interface{}, error) {
	payload, ok := ms[token]
	if !ok {
		return nil, fmt.Errorf("not found: %v", token)
	}
	return payload, nil
}

var tokenLetters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

const tokenLength = 6

func random() (string, error) {
	buf := make([]byte, tokenLength)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	for i, v := range buf {
		buf[i] = tokenLetters[v%byte(len(tokenLetters))]
	}
	return string(buf), nil
}

package token

type Store interface {
	Store(payload interface{}) (string, error)
	Fetch(token string) (interface{}, error)
}

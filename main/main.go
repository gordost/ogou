package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/ogou/token"
)

var handler = func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PUT":
		qs, ok := r.URL.Query()["payload"]
		if !ok || len(qs[0]) < 1 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing: request\n"))
			return
		}
		token, err := store.Store(qs[0])
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("%v\n", token)))
	case "GET":
		qs, ok := r.URL.Query()["token"]
		if !ok || len(qs[0]) < 1 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing: request\n"))
			return
		}
		payload, err := store.Fetch(qs[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("not found\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("%v\n", payload)))
	}
}

var listHandler = func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	enumFunc := func(token string, payload interface{}, valid bool, ttl time.Duration) {
		s := ""
		if !valid {
			s = "*expired"
		}
		w.Write([]byte(fmt.Sprintf("%v %8s [ttl:%8dms]: %v\n", token, s, -ttl.Nanoseconds()/(1000*1000), payload)))
	}
	tokenstore.Enum(enumFunc)
}

var (
	store      token.Store
	tokenstore *token.TokenStore
	ttl        = flag.Int("ttl", 10, "Time To Live (secs)")
)

func init() {
	flag.Parse()
	store = token.NewTokenStore(time.Duration(*ttl)*time.Second, 0)
	tokenstore, _ = store.(*token.TokenStore)
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/list", listHandler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}

}

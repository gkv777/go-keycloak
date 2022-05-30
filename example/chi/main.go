package main

import (
	"net/http"
	"time"

	"github.com/gkv777/keycloak"
	"github.com/go-chi/chi/v5"
)

const (
	clientId = "go-keycloak"
	secret   = "jQ9XWHdxIP5lYqyqh1DMWo4trbqgc8qN"
	realm    = "GMPRO"
)

func main() {
	keycloak := keycloak.NewKeycloak(
		"http://localhost:8086",
		clientId,
		secret,
		realm,
		time.Second*5,
	)

	r := chi.NewRouter()
	r.Post("/login", keycloak.LoginHandler())
	r.Route("/secret", func(r chi.Router) {
		r.Use(keycloak.AuthMiddleware)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome to secret!"))
		})
	})

	http.ListenAndServe(":8888", r)

}

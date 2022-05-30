package main

import (
	"net/http"
	"time"

	"github.com/gkv777/keycloak"
	"github.com/go-chi/chi/v5"
)

const (
	clientId = "go-keycloak"
	//secret   = "jQ9XWHdxIP5lYqyqh1DMWo4trbqgc8qN"
	secret = "amWVdSiKSIURDzq8dG1o2EMHkbHP6kSs"
	realm  = "GMPRO"
)

func main() {
	kcloak := keycloak.NewKeycloak(
		"http://localhost:8086",
		clientId,
		secret,
		realm,
		time.Second*5,
	)

	r := chi.NewRouter()
	r.Post("/login", kcloak.LoginHandler())
	r.Route("/secret", func(r chi.Router) {
		r.Use(kcloak.AuthMiddleware)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			login := r.Context().Value(keycloak.KeycloakUserLogin).(string)
			w.Write([]byte("welcome to secret!"))
			w.Write([]byte(login))
		})
	})

	http.ListenAndServe(":8888", r)

}

package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gkv777/keycloak"
	"github.com/go-chi/chi/v5"
)

const (
	clientId = "go-keycloak"
	secret   = "jQ9XWHdxIP5lYqyqh1DMWo4trbqgc8qN"
	//secret = "amWVdSiKSIURDzq8dG1o2EMHkbHP6kSs"
	realm = "GMPRO"
)

func main() {
	kcloak := keycloak.NewKeycloak(
		"http://localhost:8086",
		clientId,
		secret,
		realm,
		false,
		time.Second*5,
	)

	//
	secretPermission := keycloak.Perm{
		Path:   "/secret/",
		Method: "GET",
		Roles:  []string{"waybills2_worker"},
	}
	kcloak.AddPermissions(secretPermission)

	r := chi.NewRouter()
	r.Post("/login", kcloak.LoginHandler())
	r.Post("/refresh", kcloak.RefreshHandler())
	r.Route("/secret", func(r chi.Router) {
		r.Use(kcloak.AuthMiddleware)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			l := r.Context().Value(keycloak.UserLoginCtx).(string)
			log.Println(l)

			if login, err := kcloak.GetCtx(r.Context(), keycloak.UserLoginCtx); err != nil {
				w.Write([]byte("no login name for user <br/>"))
			} else {
				w.Write([]byte(login))
				w.Write([]byte("<br/>"))
			}
			w.Write([]byte("welcome to secret!"))

		})
	})

	http.ListenAndServe(":8888", r)

}

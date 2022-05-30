package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v11"
	"github.com/golang-jwt/jwt/v4"
)

var ErrLogin = errors.New("Auth error")

type KeycloakCtx string

var (
	KeycloakUserLogin KeycloakCtx = "userLogin"
	KeycloakUserEmail KeycloakCtx = "userEmail"
	KeycloakUserName  KeycloakCtx = "userName"
	KeycloakUserRoles KeycloakCtx = "userRoles"
)

type userInfo struct {
	Login    string
	Email    string
	FullName string
	Roles    []string
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type Keycloak struct {
	gocloak      gocloak.GoCloak
	clientId     string
	clientSecret string
	realm        string
	timeout      time.Duration
}

func NewKeycloak(path, id, secret, realm string, timeout time.Duration) *Keycloak {
	return &Keycloak{
		gocloak:      gocloak.NewClient(path),
		clientId:     id,
		clientSecret: secret,
		realm:        realm,
		timeout:      timeout,
	}
}

func (k *Keycloak) Login(ctx context.Context, user, passwd string) (*gocloak.JWT, error) {
	ctx, _ = context.WithTimeout(ctx, k.timeout)
	jwt, err := k.gocloak.Login(ctx, k.clientId, k.clientSecret, k.realm, user, passwd)
	if err != nil {
		return nil, err
	}
	return jwt, nil
}

func (k *Keycloak) UserInfo(jwt string) (*gocloak.UserInfo, error) {
	info, err := k.gocloak.GetUserInfo(context.Background(), jwt, k.realm)
	if err != nil {
		return nil, err
	}
	return info, err
}

func (k *Keycloak) CheckToken(ctx context.Context, token string) (*userInfo, error) {
	res, err := k.gocloak.RetrospectToken(context.Background(), token, k.clientId, k.clientSecret, k.realm)
	if err != nil {
		return nil, err
	}
	if !*res.Active {
		return nil, ErrLogin
	}

	at, _, err := k.gocloak.DecodeAccessToken(context.Background(), token, k.realm)
	if err != nil {

		return nil, err
	}

	pclaim, ok := at.Claims.(*jwt.MapClaims)
	if !ok {
		log.Println("error type conv")
	}

	claim := *pclaim
	//log.Println(claim)

	access := claim["realm_access"].(map[string]interface{})
	iroles := access["roles"].([]interface{})

	var roles []string
	for _, r := range iroles {
		roles = append(roles, r.(string))
	}

	ui := &userInfo{
		Login:    claim["preferred_username"].(string),
		Email:    claim["email"].(string),
		FullName: claim["name"].(string),
		Roles:    roles,
	}

	//log.Println(cl)
	//log.Println()

	//cl, ok := claims.(*jwt.MapClaims)

	//log.Printf("%#v", at)
	//log.Println()
	//log.Printf("%#v", claims)
	//log.Println()
	return ui, nil
}

func (k *Keycloak) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		jwt, err := k.Login(context.Background(), req.Username, req.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		resp := &loginResponse{
			AccessToken:  jwt.AccessToken,
			RefreshToken: jwt.RefreshToken,
			ExpiresIn:    jwt.ExpiresIn,
		}

		res, _ := json.Marshal(resp)

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(res)

	}
}

func (k Keycloak) extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func (k *Keycloak) AuthMiddleware(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		if token == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// extract Bearer token
		token = k.extractBearerToken(token)

		if token == "" {
			http.Error(w, "Bearer Token missing", http.StatusUnauthorized)
			return
		}

		//// call Keycloak API to verify the access token

		//jwtj, _ := json.Marshal(jwt)
		//fmt.Printf("token: %v\n", string(jwtj))

		// check if the token isn't expired and valid
		//if !*result.Active {
		//	http.Error(w, "Invalid or expired Token", http.StatusUnauthorized)
		//	return
		//}

		ctx, _ := context.WithTimeout(context.Background(), k.timeout)
		ui, err := k.CheckToken(ctx, token)
		if err != nil {
			http.Error(w, "Invalid or expired Token", http.StatusUnauthorized)
			return
		}

		uCtx := context.WithValue(r.Context(), KeycloakUserLogin, ui.Login)
		uCtx = context.WithValue(uCtx, KeycloakUserEmail, ui.Email)
		uCtx = context.WithValue(uCtx, KeycloakUserName, ui.FullName)
		uCtx = context.WithValue(uCtx, KeycloakUserRoles, strings.Join(ui.Roles, ","))

		next.ServeHTTP(w, r.WithContext(uCtx))

	}
	return http.HandlerFunc(f)
}

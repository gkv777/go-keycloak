package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v11"
	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrLogin      = errors.New("Auth error")
	ErrNoCtxValue = errors.New("this key is missing in the context")
)

type KeycloakCtx string

var (
	UserLoginCtx KeycloakCtx = "userLogin"
	UserEmailCtx KeycloakCtx = "userEmail"
	UserNameCtx  KeycloakCtx = "userName"
	UserRolesCtx KeycloakCtx = "userRoles"
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

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type Perm struct {
	Path   string
	Method string
	Roles  []string
}

type Keycloak struct {
	sync.RWMutex
	gocloak      gocloak.GoCloak
	clientId     string
	clientSecret string
	realm        string
	timeout      time.Duration
	passWoPerm   bool
	permissions  map[string]Perm
}

func NewKeycloak(path, id, secret, realm string, noPerm bool, timeout time.Duration) *Keycloak {
	return &Keycloak{
		gocloak:      gocloak.NewClient(path),
		clientId:     id,
		clientSecret: secret,
		realm:        realm,
		timeout:      timeout,
		passWoPerm:   noPerm,
		permissions:  make(map[string]Perm),
	}
}

func (k *Keycloak) AddPermissions(p Perm) {
	k.Lock()
	defer k.Unlock()

	k.permissions[getPermKey(p.Path, p.Method)] = p
}

func getPermKey(path, method string) string {
	return fmt.Sprintf("%s|%s", path, method)
}

func (k *Keycloak) CheckPerm(path, method string, ui userInfo) bool {
	k.RLock()
	defer k.RUnlock()

	p, ok := k.permissions[getPermKey(path, method)]
	if !ok {
		return k.passWoPerm
	}
	for _, ur := range ui.Roles {
		for _, pr := range p.Roles {
			if ur == pr {
				return true
			}
		}
	}
	return false
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
	log.Println(res)
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
	return ui, nil
}

func (k *Keycloak) RefreshHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx, _ := context.WithTimeout(r.Context(), k.timeout)
		jwt, err := k.gocloak.RefreshToken(ctx, req.RefreshToken, k.clientId, k.clientSecret, k.realm)
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

func (k *Keycloak) extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func (k *Keycloak) AuthMiddleware(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		if token == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		token = k.extractBearerToken(token)

		if token == "" {
			http.Error(w, "Bearer Token missing", http.StatusUnauthorized)
			return
		}

		ctx, _ := context.WithTimeout(context.Background(), k.timeout)
		ui, err := k.CheckToken(ctx, token)
		if err != nil {
			http.Error(w, "Invalid or expired Token", http.StatusUnauthorized)
			return
		}

		log.Println(r.URL.Path, r.Method)
		if !k.CheckPerm(r.URL.Path, r.Method, *ui) {
			http.Error(w, "Permission deny", http.StatusForbidden)
			return
		}

		uCtx := k.createCtx(r.Context(), *ui)
		next.ServeHTTP(w, r.WithContext(uCtx))

	}
	return http.HandlerFunc(f)
}

func (k *Keycloak) createCtx(ctx context.Context, ui userInfo) context.Context {
	log.Println(ui)
	ctx = context.WithValue(ctx, UserLoginCtx, ui.Login)
	ctx = context.WithValue(ctx, UserEmailCtx, ui.Email)
	ctx = context.WithValue(ctx, UserNameCtx, ui.FullName)
	ctx = context.WithValue(ctx, UserRolesCtx, strings.Join(ui.Roles, ","))
	return ctx
}

func (k *Keycloak) GetCtx(ctx context.Context, key KeycloakCtx) (string, error) {
	val, ok := ctx.Value(key).(string)
	log.Println(key, val)
	if !ok || val == "" {
		return "", ErrNoCtxValue
	}
	return val, nil
}

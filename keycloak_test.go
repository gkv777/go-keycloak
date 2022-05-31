package keycloak

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)


func TestKeycloakAddPremissions(t *testing.T) {

	k := NewKeycloak("http://abc:8000", "client", "secret", "realm", true, time.Hour)
	require.Equal(t, 0, len(k.permissions))

	perm:= Perm{
		Path:   "abc",
		Method: "POST",
		Roles:  []string{"role1"},
	}

	k.AddPermissions(perm)
	require.Equal(t, 1, len(k.permissions))
	
	p, ok := k.permissions[getPermKey("abc", "POST")]
	require.Equal(t, true, ok)
	require.Equal(t, "role1", p.Roles[0])

}

func TestKeycloakCherPerm(t *testing.T) {
	ui := userInfo{
		Login:    "abc",
		Email:    "abc@mail.com",
		FullName: "ABC ABC",
		Roles:    []string{"role1", "role2", "role3"},
	}

	k1:= NewKeycloak("abc:8000", "1", "2", "3", true, time.Second * 5)

	tcs:= map[string]struct{
		path, method string
		roles []string
		res, noPerm bool

	}{
		"exist and ok": {
			path: "path1",
			method: "GET",
			roles: []string{"role5", "role1"},
			res: true,
			noPerm : true,
		},
		"not exist and ok": {
			path: "path1",
			method: "GET",
			roles: []string{"role5"},
			res: false,
			noPerm : true,
		},
	}

	for name, tc := range tcs {
		t.Run(name + "_1", func(t *testing.T) {
			k1.passWoPerm = tc.noPerm
			r:= Perm{
				Path:   tc.path,
				Method: tc.method,
				Roles:  tc.roles,
			}
			k1.AddPermissions(r)
			res := k1.CheckPerm(tc.path, tc.method, ui)
			require.Equal(t, tc.res, res)
		})
	}

	for name, tc := range tcs {
		t.Run(name + "_2", func(t *testing.T) {
			k1.passWoPerm = tc.noPerm
			r:= Perm{
				Path:   tc.path,
				Method: tc.method,
				Roles:  tc.roles,
			}
			k1.AddPermissions(r)
			res := k1.CheckPerm("bde", "POST", ui)
			require.Equal(t, true, res)
		})
	}

	for name, tc := range tcs {
		t.Run(name + "_3", func(t *testing.T) {
			k1.passWoPerm = false
			r:= Perm{
				Path:   tc.path,
				Method: tc.method,
				Roles:  tc.roles,
			}
			k1.AddPermissions(r)
			res := k1.CheckPerm("bde", "POST", ui)
			require.Equal(t, false, res)
		})
	}

}

func TestKeycloakCtx(t *testing.T) {
	ui := userInfo{
		Login:    "abc",
		Email:    "abc@mail.com",
		FullName: "ABC ABC",
		Roles:    []string{"role1", "role2", "role3"},
	}

	k1:= NewKeycloak("abc:8000", "1", "2", "3", true, time.Second * 5)

	ctx:= k1.createCtx(context.TODO(), ui)

	login, err:= k1.GetCtx(ctx, UserLoginCtx)
	require.NoError(t, err)
	require.Equal(t, ui.Login, login)


}

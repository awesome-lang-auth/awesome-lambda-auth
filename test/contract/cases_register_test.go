package contract

import "testing"

func init() {
	register(
		Case{
			Name:  "register/created-shape",
			Doc:   "§3.7 — POST /register answers 201 {\"success\":true,\"userId\":\"<id>\"}",
			Needs: []Capability{CapRegister},
			Run: func(t *testing.T, e *Env) {
				acct := randomAccount()
				r := e.NewClient().POST(t, "/register", body{"email": acct.Email, "password": acct.Password})
				r.mustStatus(t, 201)

				m := r.obj(t)
				if m["success"] != true {
					t.Errorf(`want "success":true, got %v\n  %s`, m["success"], r.where())
				}
				if id, _ := m["userId"].(string); id == "" {
					t.Errorf("want a non-empty userId, got %v\n  %s", m["userId"], r.where())
				}
			},
		},

		Case{
			Name:  "register/issues-no-credentials",
			Doc:   "§3.7 — the reference issues no tokens and sets no session cookie here, and the client calls POST /login next. The port answers the same since awesome-go-auth v0.13.0 (nik2208/awesome-go-auth#21), where it used to auto-authenticate",
			Needs: []Capability{CapRegister},
			Run: func(t *testing.T, e *Env) {
				// Both delivery modes: a session in either would let a
				// registration bypass whatever email-verification gate the
				// deployment configured, which is why this used to be tracked as
				// a known defect and is now demanded.
				for _, mode := range []struct {
					name string
					opts []reqOpt
				}{
					{"cookie", nil},
					{"bearer", []reqOpt{BearerStrategy()}},
				} {
					acct := randomAccount()
					r := e.NewClient().POST(t, "/register", body{"email": acct.Email, "password": acct.Password}, mode.opts...)
					r.mustStatusIn(t, 200, 201)
					m := r.obj(t)
					if id, _ := m["userId"].(string); id == "" {
						t.Errorf("%s registration: want a non-empty userId, got %v\n  %s", mode.name, m["userId"], r.where())
					}
					for _, credential := range []string{"accessToken", "refreshToken"} {
						if c := r.cookie(credential); c != nil {
							t.Errorf("%s registration set the %s cookie (%s); the reference issues no session on POST /register\n  %s",
								mode.name, credential, c.Name, r.where())
						}
						if _, ok := m[credential]; ok {
							t.Errorf("%s registration put %q in the body; the reference issues no session on POST /register\n  %s",
								mode.name, credential, r.where())
						}
					}
				}
			},
		},
	)
}

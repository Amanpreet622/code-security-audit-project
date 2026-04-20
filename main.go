package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type ClaimsPage struct {
	Claims map[string]interface{}
}

var (
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")

	// Fix: using HTTPS instead of HTTP to secure communication
	redirectURL = "https://localhost:8080/callback"

	issuerURL = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_VSFgetsPW"

	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
)

func init() {
	var err error

	provider, err = oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		log.Fatalf("Error creating provider: %v", err)
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

// Fix: generate secure random state to prevent attacks
func generateState() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "fallbackstate"
	}
	return hex.EncodeToString(b)
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h1>Login App</h1><a href="/login">Login</a>`)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	// Fix: using generated random state instead of hardcoded value
	state := generateState()

	http.SetCookie(w, &http.Cookie{
		Name:  "oauth_state",
		Value: state,
		Path:  "/",
	})

	url := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Fix: validate state to prevent CSRF attacks
	cookie, err := r.Cookie("oauth_state")
	if err != nil || cookie.Value != state {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token error", http.StatusInternalServerError)
		return
	}

	// Fix: check if id_token exists before using it
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Missing ID token", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Verify error", http.StatusInternalServerError)
		return
	}

	claims := map[string]interface{}{}
	idToken.Claims(&claims)

	// Fix: only expose necessary safe fields (avoid sensitive data leak)
	filteredClaims := map[string]interface{}{
		"email": claims["email"],
		"name":  claims["name"],
	}

	pageData := ClaimsPage{Claims: filteredClaims}

	tmpl := `<h2>User Info</h2>
	<ul>{{range $k,$v := .Claims}}<li>{{$k}}: {{$v}}</li>{{end}}</ul>`

	t := template.Must(template.New("page").Parse(tmpl))
	t.Execute(w, pageData)
}

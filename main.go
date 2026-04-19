package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// simple struct to show user claims on page
type ClaimsPage struct {
	Claims map[string]interface{}
}

var (
	// getting client credentials from environment variables 
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")

	redirectURL = "http://localhost:8080/callback"

	// cognito issuer URL
	issuerURL = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_VSFgetsPW"

	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
)

func init() {
	var err error

	// creating OIDC provider
	provider, err = oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		log.Fatalf("Error creating provider: %v", err)
	}

	// verifying token with client ID
	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// OAuth2 configuration
	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

func main() {
	// defining routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)

	fmt.Println("Server started at http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// homepage with login link
	fmt.Fprint(w, `<h1>Login App</h1><a href="/login">Login</a>`)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	state := "12345"

	url := oauth2Config.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	code := r.URL.Query().Get("code")

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token error", http.StatusInternalServerError)
		return
	}

	rawIDToken, _ := token.Extra("id_token").(string)

	// verifying token
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Verify error", http.StatusInternalServerError)
		return
	}

	// extracting claims from token
	claims := map[string]interface{}{}
	idToken.Claims(&claims)

	pageData := ClaimsPage{Claims: claims}

	tmpl := `<h2>User Info</h2>
	<ul>{{range $k,$v := .Claims}}<li>{{$k}}: {{$v}}</li>{{end}}</ul>`

	t := template.Must(template.New("page").Parse(tmpl))

	t.Execute(w, pageData)
}
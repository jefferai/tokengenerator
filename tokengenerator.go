package main // import "github.com/jefferai/tokengenerator"

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/pborman/uuid"
)

type TokenResponse struct {
	Token        string `json:"token"`
	ValidSeconds int64  `json:"valid_seconds"`
	NumUses      int64  `json:"num_uses"`
}

func generateToken(w http.ResponseWriter, r *http.Request) {
	client, err := api.NewClient(&api.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	if err != nil {
		panic(err)
	}
	if client == nil {
		panic("Returned Vault client was nil")
	}

	tokenUUID := uuid.NewRandom().String()

	secret, err := client.Logical().Write("auth/token/create", map[string]interface{}{
		"policies": []string{"poml-secrets"},
		"orphan":   true,
	})
	if err != nil {
		panic(err)
	}
	if secret == nil {
		panic("Returned secret was nil")
	}
	if secret.Auth == nil {
		panic("Returned auth was nil")
	}

	_, err = client.Logical().Write("secret/pomltokens/"+tokenUUID, map[string]interface{}{
		"token": secret.Auth.ClientToken,
	})
	if err != nil {
		panic(err)
	}

	secret, err = client.Logical().Write("auth/token/create", map[string]interface{}{
		"policies": []string{"fetch-poml-tokens"},
		"orphan":   true,
		"lease":    "300s",
		"num_uses": 1,
		"meta": map[string]interface{}{
			"permtoken": tokenUUID,
		},
	})
	if err != nil {
		panic(err)
	}
	if secret == nil {
		panic("Returned secret was nil")
	}
	if secret.Auth == nil {
		panic("Returned auth was nil")
	}

	tokenResponse := &TokenResponse{
		Token:        secret.Auth.ClientToken,
		ValidSeconds: 300,
		NumUses:      1,
	}
	b, _ := json.Marshal(tokenResponse)
	fmt.Fprintf(w, "%s", html.EscapeString(string(b)))
}

func main() {
	http.HandleFunc("/", generateToken)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

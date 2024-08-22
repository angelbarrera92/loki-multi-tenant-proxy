package auth

import (
	"context"
	"crypto/subtle"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
	"go.uber.org/zap"

	"github.com/giantswarm/grafana-multi-tenant-proxy/internal/app/grafana-multi-tenant-proxy/config"
)

const (
	readUser = "read"
)

// Struct to represent the interesting part of the OAuth token payload section
type Payload struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
}

type OAuthAuthenticator struct {
	token      string
	authConfig *config.AuthenticationConfig
	logger     *zap.Logger
}

// Useful for testing and mock validate function
var validateFunc = validate

func (a OAuthAuthenticator) Authenticate(r *http.Request) (bool, string) {
	// Decode OAuth token payload section
	payload, err := extractPayload(a.token)
	if err != nil {
		a.logger.Error(fmt.Sprintf("Error decoding token payload %s", a.token), zap.Error(err))
		return false, ""
	}

	// Token validation against identity provider
	err = validateFunc(a.token, payload, r.Context())
	if err != nil {
		a.logger.Error(fmt.Sprintf("Error while validating OAuth token against identity provider %s", a.token), zap.Error(err))
		return false, ""
	}
	// Retrieve OrgId for user 'read'
	for _, v := range a.authConfig.Users {
		// Retrieve user 'read' and get OrgID
		if subtle.ConstantTimeCompare([]byte(readUser), []byte(v.Username)) == 1 {
			if !a.authConfig.KeepOrgID {
				return true, v.OrgID
			} else {
				return true, ""
			}
		}
	}
	return false, ""
}

func (a OAuthAuthenticator) OnAuthenticationError(w http.ResponseWriter) {
	a.logger.Error("OAuth authentication failed")
	w.WriteHeader(401)
	w.Write([]byte("Unauthorised\n"))
}

// extractPayload decodes the payload section of the OAuth token
func extractPayload(token string) (Payload, error) {
	// Get payload section from the token
	sections := strings.Split(token, ".")
	if len(sections) <= 1 {
		return Payload{}, errors.New("invalid token")
	}
	payload := sections[1]
	payloadDecoded, err := b64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Payload{}, err
	}

	var p Payload
	err = json.Unmarshal(payloadDecoded, &p)
	return p, err
}

// validate validates the OAuth token against Dex
func validate(token string, payload Payload, ctx context.Context) error {
	oauthUrl := os.Getenv("OAUTH_PROVIDER_URL")
	if oauthUrl == "" {
		return errors.New("OAUTH_PROVIDER_URL environment variable not set")
	}
	if oauthUrl != payload.Issuer {
		return fmt.Errorf("invalid issuer %s, expected issuer %s", payload.Issuer, oauthUrl)
	}
	// Initialize a provider by specifying dex's issuer URL.
	provider, err := oidc.NewProvider(ctx, payload.Issuer)
	if err != nil {
		return err
	}
	// Create an ID token parser, but only trust ID tokens issued to 'clientId'
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: payload.Audience})
	// Verify token validity
	_, err = idTokenVerifier.Verify(ctx, token)
	return err
}

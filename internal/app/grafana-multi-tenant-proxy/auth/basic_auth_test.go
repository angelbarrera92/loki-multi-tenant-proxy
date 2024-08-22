package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/giantswarm/grafana-multi-tenant-proxy/internal/app/grafana-multi-tenant-proxy/config"
)

func TestBasicAuthenticator_Authenticate(t *testing.T) {
	authConfig := &config.AuthenticationConfig{
		Users: []config.User{
			{
				Username: "user1",
				Password: "pass1",
				OrgID:    "org1",
			},
			{
				Username: "user2",
				Password: "pass2",
				OrgID:    "org2",
			},
		},
		KeepOrgID: false,
	}

	logger := zap.NewNop()

	tests := []struct {
		name     string
		user     string
		pwd      string
		expected bool
		orgID    string
	}{
		{
			name:     "Valid credentials",
			user:     "user1",
			pwd:      "pass1",
			expected: true,
			orgID:    "org1",
		},
		{
			name:     "Invalid credentials",
			user:     "user1",
			pwd:      "wrongpass",
			expected: false,
			orgID:    "",
		},
		{
			name:     "Empty credentials",
			user:     "",
			pwd:      "",
			expected: false,
			orgID:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := BasicAuthenticator{
				user:       tt.user,
				pwd:        tt.pwd,
				authConfig: authConfig,
				logger:     logger,
			}

			result, orgID := auth.Authenticate(&http.Request{})

			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.orgID, orgID)
		})
	}
}

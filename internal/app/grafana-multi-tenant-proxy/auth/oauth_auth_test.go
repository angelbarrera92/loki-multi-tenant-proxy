package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/giantswarm/grafana-multi-tenant-proxy/internal/app/grafana-multi-tenant-proxy/config"
)

func TestOAuthAuthenticator_Authenticate(t *testing.T) {
	authConfig := &config.AuthenticationConfig{
		Users: []config.User{
			{
				Username: "read",
				Password: "passread",
				OrgID:    "giantswarm|default|wc-1|wc-2",
			},
			{
				Username: "user1",
				Password: "pass1",
				OrgID:    "org1",
			},
		},
		KeepOrgID: false,
	}

	logger := zap.NewNop()

	tests := []struct {
		name        string
		token       string
		expected    bool
		expectedOrg string
		validateErr error
	}{
		{
			name:        "Valid token",
			token:       "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg5MjlhMzdkM2Y2OGM0Njg1OTJjOGIyODhhYjBhMTk0OGQ3MmQ4YzUifQ.eyJpc3MiOiJodHRwczovL2RleC5nb2xlbS5nYXdzLmdpZ2FudGljLmlvIiwic3ViIjoiQ2lRMU5UTTNaakk1WkMwek5UWTNMVFExTW1FdE9UQmxNUzAzTnpNeU5EUTVZalUzWldFU0RXZHBZVzUwYzNkaGNtMHRZV1EiLCJhdWQiOiIycVJnTmI1cVFCazNRcVd4STFXTGdCNXpUUTFNNGVCKyIsImV4cCI6MTcwNjcxNzAxNywiaWF0IjoxNzA2NzE1MjE3LCJhdF9oYXNoIjoiYndsX0tYSUJtbHJUbm9IRXN2RUNLdyIsImVtYWlsIjoibWFyaWVAZ2lhbnRzd2FybS5pbyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiZ2lhbnRzd2FybS1hZDpnaWFudHN3YXJtLWFkbWlucyIsImdpYW50c3dhcm0tYWQ6R1MgU3VwcG9ydCAtIE1TIHRlYW1zIiwiZ2lhbnRzd2FybS1hZDpHaWFudCBTd2FybSBHbG9iYWwiLCJnaWFudHN3YXJtLWFkOkdpYW50U3dhcm0iLCJnaWFudHN3YXJtLWFkOkdpYW50IFN3YXJtIEVVIiwiZ2lhbnRzd2FybS1hZDpEZXZlbG9wZXJzIl0sIm5hbWUiOiJNYXJpZSBSb3F1ZSJ9.UyfIohHXBVocgv2nb-lgwVU09LJDwzHOHDb20HVZPTPMVBTLPWPzCgryg2KCXxAO1eyspdbcEQA-ZnQoqW_S6QajVyMCQyqLAECRa5h90dIvENvgj3jdcjDhCZl8q5k7Jl0WUMsBFMFMoaa3GKslM0tNcb5s-g1m0ylZocKu46qbJpiF7xWVg4ak_eWoyjb7lvBmCOSWavNHvl0Wc0Rq8HlwZHQl9Bmr5w1gZYKBcdYeMTL9_I0vnTF3UkQsvpQRsVUG9j9z86rCx3T8LsQcY_4jpOnvRVvFRbTWAWcbErvDdfOdte1TVWgBVttKq-WNBgS2HVVjk8jUAlU62k4MPA",
			expected:    true,
			expectedOrg: "giantswarm|default|wc-1|wc-2",
			validateErr: nil,
		},
		{
			name:        "Invalid token",
			token:       "invalid_token",
			expected:    false,
			expectedOrg: "",
			validateErr: errors.New("validation error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := OAuthAuthenticator{
				token:      tt.token,
				authConfig: authConfig,
				logger:     logger,
			}

			validateFunc = func(token string, payload Payload, ctx context.Context) error {
				return nil
			}

			result, orgID := auth.Authenticate(&http.Request{})

			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.expectedOrg, orgID)
		})
	}
}

func TestOAuthAuthenticator_extractPayload(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg5MjlhMzdkM2Y2OGM0Njg1OTJjOGIyODhhYjBhMTk0OGQ3MmQ4YzUifQ.eyJpc3MiOiJodHRwczovL2RleC5nb2xlbS5nYXdzLmdpZ2FudGljLmlvIiwic3ViIjoiQ2lRMU5UTTNaakk1WkMwek5UWTNMVFExTW1FdE9UQmxNUzAzTnpNeU5EUTVZalUzWldFU0RXZHBZVzUwYzNkaGNtMHRZV1EiLCJhdWQiOiIycVJnTmI1cVFCazNRcVd4STFXTGdCNXpUUTFNNGVCKyIsImV4cCI6MTcwNjcxNzAxNywiaWF0IjoxNzA2NzE1MjE3LCJhdF9oYXNoIjoiYndsX0tYSUJtbHJUbm9IRXN2RUNLdyIsImVtYWlsIjoibWFyaWVAZ2lhbnRzd2FybS5pbyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiZ2lhbnRzd2FybS1hZDpnaWFudHN3YXJtLWFkbWlucyIsImdpYW50c3dhcm0tYWQ6R1MgU3VwcG9ydCAtIE1TIHRlYW1zIiwiZ2lhbnRzd2FybS1hZDpHaWFudCBTd2FybSBHbG9iYWwiLCJnaWFudHN3YXJtLWFkOkdpYW50U3dhcm0iLCJnaWFudHN3YXJtLWFkOkdpYW50IFN3YXJtIEVVIiwiZ2lhbnRzd2FybS1hZDpEZXZlbG9wZXJzIl0sIm5hbWUiOiJNYXJpZSBSb3F1ZSJ9.UyfIohHXBVocgv2nb-lgwVU09LJDwzHOHDb20HVZPTPMVBTLPWPzCgryg2KCXxAO1eyspdbcEQA-ZnQoqW_S6QajVyMCQyqLAECRa5h90dIvENvgj3jdcjDhCZl8q5k7Jl0WUMsBFMFMoaa3GKslM0tNcb5s-g1m0ylZocKu46qbJpiF7xWVg4ak_eWoyjb7lvBmCOSWavNHvl0Wc0Rq8HlwZHQl9Bmr5w1gZYKBcdYeMTL9_I0vnTF3UkQsvpQRsVUG9j9z86rCx3T8LsQcY_4jpOnvRVvFRbTWAWcbErvDdfOdte1TVWgBVttKq-WNBgS2HVVjk8jUAlU62k4MPA"
	expectedPayload := Payload{
		Issuer:   "https://dex.golem.gaws.gigantic.io",
		Audience: "2qRgNb5qQBk3QqWxI1WLgB5zTQ1M4eB+",
	}

	auth := OAuthAuthenticator{
		token: token,
	}

	payload, err := extractPayload(auth.token)

	assert.NoError(t, err)
	assert.Equal(t, expectedPayload, payload)
}

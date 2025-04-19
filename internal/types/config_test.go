package types

import (
	"testing"
)

func TestAuthConfig_IsKnownDomain(t *testing.T) {
	type fields struct {
		Users           Users
		OauthWhitelist  string
		SessionExpiry   int
		DomainSecrets   map[string]string
		Secret          string
		CookieSecure    bool
		Domains         []string
		LoginTimeout    int
		LoginMaxRetries int
	}
	type args struct {
		domain string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "known domain",
			fields: fields{
				Domains: []string{"example.com", "int.example.com"},
			},
			args: args{
				domain: "example.com",
			},
			want: true,
		},
		{
			name: "unknown domain",
			fields: fields{
				Domains: []string{"example.com", "int.example.com"},
			},
			args: args{
				domain: "fake.com",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := AuthConfig{
				Users:           tt.fields.Users,
				OauthWhitelist:  tt.fields.OauthWhitelist,
				SessionExpiry:   tt.fields.SessionExpiry,
				DomainSecrets:   tt.fields.DomainSecrets,
				Secret:          tt.fields.Secret,
				CookieSecure:    tt.fields.CookieSecure,
				Domains:         tt.fields.Domains,
				LoginTimeout:    tt.fields.LoginTimeout,
				LoginMaxRetries: tt.fields.LoginMaxRetries,
			}
			if got := ac.IsKnownDomain(tt.args.domain); got != tt.want {
				t.Errorf("AuthConfig.IsKnownDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthConfig_GetDomainSecret(t *testing.T) {
	type fields struct {
		Users           Users
		OauthWhitelist  string
		SessionExpiry   int
		DomainSecrets   map[string]string
		Secret          string
		CookieSecure    bool
		Domains         []string
		LoginTimeout    int
		LoginMaxRetries int
	}
	type args struct {
		domain string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "known domain with secret",
			fields: fields{
				DomainSecrets: map[string]string{"example.com": "secret1"},
				Domains:       []string{"example.com", "int.example.com"},
				Secret:        "my-secret",
			},
			args: args{
				domain: "example.com",
			},
			want: "secret1",
		},
		{
			name: "known domain without secret",
			fields: fields{
				DomainSecrets: map[string]string{"int.example.com": "secret1"},
				Domains:       []string{"example.com", "int.example.com"},
				Secret:        "my-secret",
			},
			args: args{
				domain: "example.com",
			},
			want: "my-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := AuthConfig{
				Users:           tt.fields.Users,
				OauthWhitelist:  tt.fields.OauthWhitelist,
				SessionExpiry:   tt.fields.SessionExpiry,
				DomainSecrets:   tt.fields.DomainSecrets,
				Secret:          tt.fields.Secret,
				CookieSecure:    tt.fields.CookieSecure,
				Domains:         tt.fields.Domains,
				LoginTimeout:    tt.fields.LoginTimeout,
				LoginMaxRetries: tt.fields.LoginMaxRetries,
			}
			if got := ac.GetDomainSecret(tt.args.domain); got != tt.want {
				t.Errorf("AuthConfig.GetDomainSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

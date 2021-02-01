package jwt

import (
	"bytes"
	"encoding/json"
	auth "github.com/z26100/auth-go"
	"testing"
)

var (
	keycloakSampleResponse = `{"keys":[{"kid":"O2i7Tf9NX9kqMiZKsGOS9EYa2cSpE-HxY_pbnz8aTgs","kty":"RSA","alg":"RS256","use":"sig","n":"nzuNxgPb0Lt7mWPgKDx6u6kGr_Ir_w0x6Z2Atu2EWAnoo7e1oxZYBbL-jeRwcySG_jmVh3lT8vwwKD-k0J5ZYj0YV6A-EBEQJAxgw7sF_0Cx7IdBB5zTVExHP_Pw0JXhr3ACeaHQiNXt7fxhRwwncUMkA5lmxsPSfaH7KOxAN2DlidR0C01n0KeRjPT79Vhs1mEmt08UIcXAMZBUJlZERYusFpFDTdsSN3fAIHng54misVL7NYMkWEdTndENJkAfXN9OngLGk8WlR6Kiq7nPW02bd7qBItVLAhR-4piEeYl1n5mnp0eMXe1KvCV0WAtttsrqQ0Vp0Gr-BfmMu8xGbQ","e":"AQAB","x5c":["MIIClTCCAX0CBgFuzECHbzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANuZ2UwHhcNMTkxMjAzMTQ1MTUxWhcNMjkxMjAzMTQ1MzMxWjAOMQwwCgYDVQQDDANuZ2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfO43GA9vQu3uZY+AoPHq7qQav8iv/DTHpnYC27YRYCeijt7WjFlgFsv6N5HBzJIb+OZWHeVPy/DAoP6TQnlliPRhXoD4QERAkDGDDuwX/QLHsh0EHnNNUTEc/8/DQleGvcAJ5odCI1e3t/GFHDCdxQyQDmWbGw9J9ofso7EA3YOWJ1HQLTWfQp5GM9Pv1WGzWYSa3TxQhxcAxkFQmVkRFi6wWkUNN2xI3d8AgeeDniaKxUvs1gyRYR1Od0Q0mQB9c306eAsaTxaVHoqKruc9bTZt3uoEi1UsCFH7imIR5iXWfmaenR4xd7Uq8JXRYC222yupDRWnQav4F+Yy7zEZtAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABS1E56ij3o353OkR1+AYFMIRE1HN3aG+9wBlpHQSvIBTIO+cQr1ZfGrlL5RPetDD+pEoH2ygY+EVS1egVemiDTX1CyAxqViWIupka7xz+aXP95outRLV9gIrEbFY9eSaTvfB2Kl4t3QwPZSukdkDTMcj5QG399W5J/3ff1nHed9XP4wr0jDSq16Rv1B8niDq/dJ65pL/AF9tt7dtBm3ZptFBVKTzDXAkOjOy0KwMaUNiaBFFAZmfDvOuuLIHxOoqQmRGFokWx7/hluWZA1z6Wj2wjcmnd53jNxqv2gKOcchv+h3tR69UtLWd7BIzwKERgHZHgXeKKX+dZnHiRAclwo="],"x5t":"ajxj3PkYFfaxgIY4cm16io3NymI","x5t#S256":"-PU2K762D3tqpGV0tnZImPWHE1XmfF9RkaO_uCDGAH0"}]}`
	expectedKey            = "MIIClTCCAX0CBgFuzECHbzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANuZ2UwHhcNMTkxMjAzMTQ1MTUxWhcNMjkxMjAzMTQ1MzMxWjAOMQwwCgYDVQQDDANuZ2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfO43GA9vQu3uZY+AoPHq7qQav8iv/DTHpnYC27YRYCeijt7WjFlgFsv6N5HBzJIb+OZWHeVPy/DAoP6TQnlliPRhXoD4QERAkDGDDuwX/QLHsh0EHnNNUTEc/8/DQleGvcAJ5odCI1e3t/GFHDCdxQyQDmWbGw9J9ofso7EA3YOWJ1HQLTWfQp5GM9Pv1WGzWYSa3TxQhxcAxkFQmVkRFi6wWkUNN2xI3d8AgeeDniaKxUvs1gyRYR1Od0Q0mQB9c306eAsaTxaVHoqKruc9bTZt3uoEi1UsCFH7imIR5iXWfmaenR4xd7Uq8JXRYC222yupDRWnQav4F+Yy7zEZtAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABS1E56ij3o353OkR1+AYFMIRE1HN3aG+9wBlpHQSvIBTIO+cQr1ZfGrlL5RPetDD+pEoH2ygY+EVS1egVemiDTX1CyAxqViWIupka7xz+aXP95outRLV9gIrEbFY9eSaTvfB2Kl4t3QwPZSukdkDTMcj5QG399W5J/3ff1nHed9XP4wr0jDSq16Rv1B8niDq/dJ65pL/AF9tt7dtBm3ZptFBVKTzDXAkOjOy0KwMaUNiaBFFAZmfDvOuuLIHxOoqQmRGFokWx7/hluWZA1z6Wj2wjcmnd53jNxqv2gKOcchv+h3tR69UtLWd7BIzwKERgHZHgXeKKX+dZnHiRAclwo="
)

const (
	oauthPublicKeyUrl = "https://keycloak.altemista.cloud/auth/realms/NGE/protocol/openid-connect/certs"
	keycloakFieldname = "x5c"
)

func TestKeycloakAdapter(t *testing.T) {
	adapter := auth.NewKeycloakAdapter(keycloakFieldname)
	var input map[string]interface{}
	err := json.Unmarshal(bytes.NewBufferString(keycloakSampleResponse).Bytes(), &input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Get(input)
	if err != nil {
		t.Fatal(err)
	}
	if result != expectedKey {
		t.Fatal("result unexpected")
	}
}

func TestReadTokenFromWebsite(t *testing.T) {
	adapter := auth.NewKeycloakAdapter(keycloakFieldname)
	provider := auth.NewWebsitePublicKeyProvider(oauthPublicKeyUrl, adapter)
	data, err := provider.Get()
	if err != nil {
		t.Fatal(err)
	}
	if data == nil {
		t.Fatal(err)
	}
}

func TestReadTokenFromFile(t *testing.T) {
	provider := auth.NewFilePublicKeyProvider("sample-pk.pem")
	data, err := provider.Get()
	if err != nil {
		t.Fatal(err)
	}
	if data == nil {
		t.Fatal(err)
	}
}

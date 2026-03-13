package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const InviteScheme = "burrow://connect/"

type InviteData struct {
	Server    string `json:"s"`
	Port      uint16 `json:"p"`
	Token     string `json:"k"`
	SNI       string `json:"sni"`
	PublicKey string `json:"pk"`
	ShortID   string `json:"sid"`
	Name      string `json:"n,omitempty"`
	CDNHost   string `json:"ch,omitempty"`
	CDNPort   uint16 `json:"cp,omitempty"`
	CDNPath   string `json:"cw,omitempty"`
	Sig       string `json:"sig,omitempty"`
}

func invitePayload(data InviteData) ([]byte, error) {
	clean := data
	clean.Sig = ""
	return json.Marshal(clean)
}

func SignInvite(data InviteData, secret string) string {
	payload, err := invitePayload(data)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func VerifyInvite(encoded string, secret string) (InviteData, error) {
	data, err := DecodeInvite(encoded)
	if err != nil {
		return InviteData{}, err
	}

	if data.Sig == "" {
		return data, nil
	}

	expected := SignInvite(data, secret)
	if !hmac.Equal([]byte(data.Sig), []byte(expected)) {
		return InviteData{}, fmt.Errorf("invalid invite signature")
	}

	return data, nil
}

func EncodeInvite(data InviteData) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal invite: %w", err)
	}
	return InviteScheme + base64.RawURLEncoding.EncodeToString(b), nil
}

func DecodeInvite(link string) (InviteData, error) {
	if !strings.HasPrefix(link, InviteScheme) {
		return InviteData{}, fmt.Errorf("invalid invite link: must start with %s", InviteScheme)
	}
	encoded := strings.TrimPrefix(link, InviteScheme)
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return InviteData{}, fmt.Errorf("decode invite: %w", err)
	}
	var data InviteData
	if err := json.Unmarshal(b, &data); err != nil {
		return InviteData{}, fmt.Errorf("unmarshal invite: %w", err)
	}
	return data, nil
}

package shared

import (
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

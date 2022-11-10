package models

type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SubDomain string `json:"subdomain"`
	// MfaRequired  string            `json:"mfa_required"`
	OwnerEmail   string            `json:"owner_email"`
	Certificates map[string]string `json:"certificate"`
}

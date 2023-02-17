package models

type Organization struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Subdomain    string            `json:"subdomain"`
	Certificates map[string]string `json:"certificate"`
}

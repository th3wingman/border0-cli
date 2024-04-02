package serviceaccount

var (
	// flags
	name         string
	tokenName    string
	description  string
	role         string
	lifetimeDays int
	jsonOutput   bool
)

type serviceAccountSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Role        string `json:"role"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type tokenSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Token     string `json:"token"`
}

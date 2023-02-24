package models

type Notification struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Enabled         bool     `json:"enabled"`
	Events          []string `json:"events"`
	WebhookURL      string   `json:"webhook_url,omitempty"`
	EmailRecipients []string `json:"email_recipients,omitempty"`
}

type NotificationUpdate struct {
	Enabled         *bool    `json:"enabled,omitempty"`
	Events          []string `json:"events,omitempty"`
	WebhookURL      *string  `json:"webhook_url,omitempty"`
	EmailRecipients []string `json:"email_recipients,omitempty"`
}

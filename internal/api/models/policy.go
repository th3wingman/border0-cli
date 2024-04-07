package models

import "time"

type CreatePolicyRequest struct {
	Name        string     `json:"name" binding:"required"`
	Description string     `json:"description"`
	PolicyData  PolicyData `json:"policy_data" binding:"required"`
	Orgwide     bool       `json:"org_wide"`
}

type UpdatePolicyRequest struct {
	Name        *string     `json:"name"`
	Description *string     `json:"description"`
	PolicyData  *PolicyData `json:"policy_data" binding:"required"`
}

type Policy struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	PolicyData  PolicyData `json:"policy_data"`
	SocketIDs   []string   `json:"socket_ids"`
	OrgID       string     `json:"org_id"`
	OrgWide     bool       `json:"org_wide"`
	CreatedAt   time.Time  `json:"created_at"`
}

type PolicyTest struct {
	Email     string `json:"email" binding:"required"`
	IPAddress string `json:"ip_address" binding:"required"`
	Time      string `json:"time" binding:"required"`
}

type PolicyTestRespone struct {
	Actions map[string][]string `json:"Actions,omitempty"`
	Info    struct {
		Allowed []string `json:"allowed,omitempty"`
		Failed  []string `json:"failed,omitempty"`
	} `json:"Info,omitempty"`
}

type PolicyData struct {
	Version   string    `json:"version"`
	Action    []string  `json:"action" mapstructure:"action"`
	Condition Condition `json:"condition" mapstructure:"condition"`
}

type Condition struct {
	Who   ConditionWho   `json:"who,omitempty" mapstructure:"who"`
	Where ConditionWhere `json:"where,omitempty" mapstructure:"where"`
	When  ConditionWhen  `json:"when,omitempty" mapstructure:"when"`
}

type ConditionWho struct {
	Email  []string `json:"email,omitempty" mapstructure:"email"`
	Domain []string `json:"domain,omitempty" mapstructure:"domain"`
}

type ConditionWhere struct {
	AllowedIP  []string `json:"allowed_ip,omitempty" mapstructure:"allowed_ip"`
	Country    []string `json:"country,omitempty" mapstructure:"country"`
	CountryNot []string `json:"country_not,omitempty" mapstructure:"country_not"`
}

type ConditionWhat struct{}

type ConditionWhen struct {
	After           string `json:"after,omitempty" mapstructure:"after"`
	Before          string `json:"before,omitempty" mapstructure:"before"`
	TimeOfDayAfter  string `json:"time_of_day_after,omitempty" mapstructure:"time_of_day_after"`
	TimeOfDayBefore string `json:"time_of_day_before,omitempty" mapstructure:"time_of_day_before"`
}

type PolicyActionUpdateRequest struct {
	Action string `json:"action" binding:"required"`
	ID     string `json:"id" binding:"required"`
}
type AddSocketToPolicyRequest struct {
	Actions []PolicyActionUpdateRequest `json:"actions" binding:"required"`
}

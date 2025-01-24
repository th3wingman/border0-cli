package models

import (
	"time"

	sdk "github.com/borderzero/border0-go/client"
)

type CreatePolicyRequest struct {
	Name        string     `json:"name" binding:"required"`
	Description string     `json:"description"`
	PolicyData  PolicyData `json:"policy_data" binding:"required"`
	Orgwide     bool       `json:"org_wide"`
	Version     string     `json:"version"`
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
	Version     string     `json:"version"`
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
	Action      []string       `json:"action,omitempty" mapstructure:"action"`
	Permissions map[string]any `json:"permissions,omitempty" mapstructure:"permissions"`
	Condition   Condition      `json:"condition" mapstructure:"condition"`
}

type Condition struct {
	Who   ConditionWho   `json:"who,omitempty" mapstructure:"who"`
	Where ConditionWhere `json:"where,omitempty" mapstructure:"where"`
	When  ConditionWhen  `json:"when,omitempty" mapstructure:"when"`
}

type ConditionWho struct {
	Email          []string `json:"email,omitempty" mapstructure:"email"`
	Domain         []string `json:"domain,omitempty" mapstructure:"domain"`
	Group          []string `json:"group,omitempty" mapstructure:"group"`
	ServiceAccount []string `json:"service_account,omitempty" mapstructure:"service_account"`
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

type Permissions struct {
	Database   *DatabasePermissions       `json:"database,omitempty"`
	SSH        *SSHPermissions            `json:"ssh,omitempty"`
	HTTP       *sdk.HTTPPermissions       `json:"http,omitempty"`
	TLS        *sdk.TLSPermissions        `json:"tls,omitempty"`
	VNC        *sdk.VNCPermissions        `json:"vnc,omitempty"`
	RDP        *sdk.RDPPermissions        `json:"rdp,omitempty"`
	VPN        *sdk.VPNPermissions        `json:"vpn,omitempty"`
	Kubernetes *sdk.KubernetesPermissions `json:"kubernetes,omitempty"`
}

type DatabasePermissions struct {
	AllowedDatabases          *[]DatabasePermission `json:"allowed_databases,omitempty"`
	MaxSessionDurationSeconds *int                  `json:"max_session_duration_seconds,omitempty"`
}

type DatabasePermission struct {
	Database          string    `json:"database"`
	AllowedQueryTypes *[]string `json:"allowed_query_types,omitempty"`
}

type SSHPermissions struct {
	Shell                     *SSHShellPermission         `json:"shell,omitempty"`
	Exec                      *SSHExecPermission          `json:"exec,omitempty"`
	SFTP                      *SSHSFTPPermission          `json:"sftp,omitempty"`
	TCPForwarding             *SSHTCPForwardingPermission `json:"tcp_forwarding,omitempty"`
	KubectlExec               *SSHKubectlExecPermission   `json:"kubectl_exec,omitempty"`
	DockerExec                *SSHDockerExecPermission    `json:"docker_exec,omitempty"`
	MaxSessionDurationSeconds *int                        `json:"max_session_duration_seconds,omitempty"`
	AllowedUsernames          *[]string                   `json:"allowed_usernames,omitempty"`
}

type SSHShellPermission struct{}

type SSHExecPermission struct {
	Commands *[]string `json:"commands,omitempty"`
}

type SSHSFTPPermission struct{}

type SSHTCPForwardingPermission struct {
	AllowedConnections *[]SSHTcpForwardingConnection `json:"allowed_connections,omitempty"`
}

type SSHTcpForwardingConnection struct {
	DestinationAddress *string `json:"destination_address,omitempty"`
	DestinationPort    *string `json:"destination_port,omitempty"`
}

type SSHKubectlExecPermission struct {
	AllowedNamespaces *[]KubectlExecNamespace `json:"allowed_namespaces,omitempty"`
}

type KubectlExecNamespace struct {
	Namespace   string             `json:"namespace"`
	PodSelector *map[string]string `json:"pod_selector,omitempty"`
}

type SSHDockerExecPermission struct {
	AllowedContainers *[]string `json:"allowed_containers,omitempty"`
}

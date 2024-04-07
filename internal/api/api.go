package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/borderzero/border0-go/types/connector"
	"github.com/borderzero/border0-go/types/service"
	"github.com/golang-jwt/jwt"
	"golang.org/x/sync/errgroup"
)

const APIUrl = "https://api.border0.com/api/v1"

var ErrUnauthorized = errors.New("invalid token, please login")
var ErrNotFound = errors.New("resource not found")

type API interface {
	GetOrganizationInfo(ctx context.Context) (*models.Organization, error)
	GetSockets(ctx context.Context) ([]models.Socket, error)
	GetSocket(ctx context.Context, socketID string) (*models.Socket, error)
	GetTunnel(ctx context.Context, socketID string, tunnelID string) (*models.Tunnel, error)
	CreateTunnel(ctx context.Context, socketID string) (*models.Tunnel, error)
	CreateSocket(ctx context.Context, socket *models.Socket) (*models.Socket, error)
	UpdateSocket(ctx context.Context, socketID string, socket models.Socket) error
	DeleteSocket(ctx context.Context, socketID string) error
	Login(email, password string) (*models.LoginResponse, error)
	GetPolicyByName(ctx context.Context, name string) (*models.Policy, error)
	AttachPolicies(ctx context.Context, socketID string, policyUUIDs []string) ([]string, error)
	DetachPolicies(ctx context.Context, socketID string, policyUUIDs []string) ([]string, error)
	GetPoliciesBySocketID(socketID string) ([]models.Policy, error)
	StartRefreshAccessTokenJob(ctx context.Context)
	GetAccessToken() string
	SignSSHKey(ctx context.Context, socketID string, key []byte) (string, string, error)
	GetUserID() (string, error)
	Evaluate(ctx context.Context, socket *models.Socket, clientIP, userEmail, sessionKey string) (allowedActions []string, info map[string][]string, err error)
	UpdateSession(update models.SessionUpdate) error
	SignSshOrgCertificate(ctx context.Context, socketID, sessionID, userEmail string, ticket, publicKey []byte) ([]byte, error)
	UploadRecording(content []byte, socketID, sessionKey, recordingID string) error
	ServerOrgCertificate(ctx context.Context, name string, csr []byte) ([]byte, error)
}

var once sync.Once

var APIImpl = (*Border0API)(nil)

type APIOption func(*Border0API)

func WithCredentials(creds *models.Credentials) APIOption {
	return func(h *Border0API) {
		h.Credentials = creds
	}
}

func WithVersion(version string) APIOption {
	return func(h *Border0API) {
		h.Version = version
	}
}

type Border0API struct {
	Credentials *models.Credentials
	Version     string
	mutex       *sync.Mutex
}

type ErrorMessage struct {
	ErrorMessage string `json:"error_message,omitempty"`
}

func NewAPI(opts ...APIOption) *Border0API {
	api := Border0API{mutex: &sync.Mutex{}}

	for _, opt := range opts {
		opt(&api)
	}

	return &api
}

func APIURL() string {
	if os.Getenv("BORDER0_API") != "" {
		return os.Getenv("BORDER0_API")
	} else {
		return APIUrl
	}
}

func getToken() (*models.Credentials, error) {
	if os.Getenv("BORDER0_ADMIN_TOKEN") != "" {
		return models.NewCredentials(os.Getenv("BORDER0_ADMIN_TOKEN"), models.CredentialsTypeToken), nil
	}

	if _, err := os.Stat(tokenfile()); os.IsNotExist(err) {
		return nil, errors.New("API: please login first (no token found)")
	}
	content, err := os.ReadFile(tokenfile())
	if err != nil {
		return nil, err
	}

	tokenString := strings.TrimRight(string(content), "\n")
	return models.NewCredentials(tokenString, models.CredentialsTypeUser), nil
}

func tokenfile() string {
	tokenfile := ""
	if runtime.GOOS == "windows" {
		tokenfile = fmt.Sprintf("%s/.border0/token", os.Getenv("APPDATA"))
	} else {
		hd, err := util.GetUserHomeDir()
		if err != nil {
			log.Fatalf("failed to determine user's home directory: %v", err)
		}
		tokenfile = fmt.Sprintf("%s/.border0/token", hd)
	}
	return tokenfile
}

func (a *Border0API) Request(method string, url string, target interface{}, data interface{}, requireAccessToken bool) error {
	jv, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	body := bytes.NewBuffer(jv)

	return a.RequestAny(method, url, target, body, "application/json", requireAccessToken)
}

func (a *Border0API) RequestAny(method string, url string, target interface{}, body *bytes.Buffer, contentType string, requireAccessToken bool) error {
	req, _ := http.NewRequest(method, fmt.Sprintf("%s/%s", APIURL(), url), body)

	//try to find the token in the environment
	if requireAccessToken && a.Credentials == nil || (a.Credentials != nil && a.Credentials.AccessToken == "") {
		token, _ := getToken()
		a.Credentials = token
	}

	if a.Credentials != nil && a.Credentials.AccessToken != "" {
		req.Header.Add("x-access-token", a.Credentials.AccessToken)
	}

	req.Header.Add("x-client-requested-with", "border0")
	if a.Version != "" {
		req.Header.Add("x-client-version", a.Version)
	}
	req.Header.Set("Content-Type", contentType)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return ErrUnauthorized
	}

	if resp.StatusCode == 429 {
		responseData, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rate limit error: %v", string(responseData))
	}

	if resp.StatusCode == 404 {
		return ErrNotFound
	}

	if resp.StatusCode < 200 || resp.StatusCode > 204 {
		var errorMessage ErrorMessage
		json.NewDecoder(resp.Body).Decode(&errorMessage)

		return fmt.Errorf("failed to create object (%d) %v", resp.StatusCode, errorMessage.ErrorMessage)
	}

	if resp.StatusCode == 204 {
		return nil
	}

	err = json.NewDecoder(resp.Body).Decode(target)
	if err != nil {
		return fmt.Errorf("failed to decode request body: %w", err)
	}

	return nil
}

func (a *Border0API) With(opt APIOption) *Border0API {
	opt(a)
	return a
}

func (a *Border0API) GetOrganizationInfo(ctx context.Context) (*models.Organization, error) {
	org := models.Organization{}

	err := a.Request("GET", "organization", &org, nil, true)
	if err != nil {
		return nil, err
	}

	return &org, nil
}

func (a *Border0API) GetSockets(ctx context.Context) ([]models.Socket, error) {
	sockets := []models.Socket{}

	err := a.Request("GET", "socket", &sockets, nil, true)
	if err != nil {
		return nil, err
	}

	return sockets, nil
}

func (a *Border0API) GetSocket(ctx context.Context, socketID string) (*models.Socket, error) {
	socket := models.Socket{}

	err := a.Request("GET", fmt.Sprintf("socket/%v", socketID), &socket, nil, true)
	if err != nil {
		return nil, err
	}

	return &socket, nil
}

func (a *Border0API) GetTunnel(ctx context.Context, socketID string, tunnelID string) (*models.Tunnel, error) {
	tunnel := models.Tunnel{}

	err := a.Request("GET", fmt.Sprintf("socket/%v/tunnel/%v", socketID, tunnelID), &tunnel, nil, true)
	if err != nil {
		return nil, err
	}

	return &tunnel, nil
}

func (a *Border0API) CreateSocket(ctx context.Context, socket *models.Socket) (*models.Socket, error) {
	s := models.Socket{}

	// Force cloud auth
	socket.CloudAuthEnabled = true

	err := a.Request("POST", "socket", &s, socket, true)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (a *Border0API) CreateTunnel(ctx context.Context, socketID string) (*models.Tunnel, error) {
	t := models.Tunnel{}

	url := fmt.Sprintf("socket/%v/tunnel", socketID)
	err := a.Request("POST", url, &t, nil, true)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func (a *Border0API) DeleteSocket(ctx context.Context, socketID string) error {
	err := a.Request("DELETE", "socket/"+socketID, nil, nil, true)
	if err != nil {
		return err
	}

	return nil
}

func (a *Border0API) UpdateSocket(ctx context.Context, socketID string, socket models.Socket) error {
	var result models.Socket

	// Force cloud auth
	socket.CloudAuthEnabled = true

	err := a.Request("PUT", "socket/"+socketID, &result, &socket, true)
	if err != nil {
		return err
	}

	return nil
}

func (a *Border0API) Login(email, password string) (*models.LoginResponse, error) {
	form := &models.LoginRequest{Email: email, Password: password}

	loginResponse := models.LoginResponse{}
	err := a.Request("POST", "login", &loginResponse, form, false)
	if err != nil {
		return nil, err
	}

	return &loginResponse, nil
}

func (a *Border0API) GetAccessToken() string {
	if a.Credentials == nil {
		return ""
	}

	return a.Credentials.AccessToken
}

type actionUpdate struct {
	Action string `json:"action" binding:"required"`
	ID     string `json:"id" binding:"required"`
}
type actionsRequest struct {
	Actions []actionUpdate `json:"actions" binding:"required"`
}

func (a *Border0API) AttachPolicies(ctx context.Context, socketID string, policyUUIDs []string) ([]string, error) {
	actions := []actionUpdate{}
	for _, policyUUID := range policyUUIDs {
		actions = append(actions, actionUpdate{Action: "add", ID: policyUUID})
	}

	actionRequest := actionsRequest{Actions: actions}
	url := fmt.Sprintf("socket/%v/policy", socketID)

	var response []string
	err := a.Request("PUT", url, &response, actionRequest, true)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (a *Border0API) DetachPolicies(ctx context.Context, socketID string, policyUUIDs []string) ([]string, error) {
	actions := []actionUpdate{}
	for _, policyUUID := range policyUUIDs {
		actions = append(actions, actionUpdate{Action: "remove", ID: policyUUID})
	}

	actionRequest := actionsRequest{Actions: actions}
	url := fmt.Sprintf("socket/%v/policy", socketID)

	var response []string
	err := a.Request("PUT", url, &response, actionRequest, true)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// CreateConnector creates a new border0 connector (v2)
func (a *Border0API) CreateConnector(
	ctx context.Context,
	name string,
	description string,
	enableBuiltInSshService bool,
	builtInSshServiceConfig *service.BuiltInSshServiceConfiguration,
) (*models.Connector, error) {
	payload := &models.Connector{Name: name, Description: description, BuiltInSshServiceEnabled: enableBuiltInSshService}
	if builtInSshServiceConfig != nil {
		payload.BuiltInSshServiceConfiguration = builtInSshServiceConfig
	}

	var connector models.Connector
	err := a.Request(http.MethodPost, "connector", &connector, payload, true)
	if err != nil {
		return nil, err
	}

	return &connector, nil
}

// CreateConnectorWithInstallToken is a connector v2 method, it creates a new border0 connector
// and connector token from an install token (invite code)
func (a *Border0API) CreateConnectorWithInstallToken(
	ctx context.Context,
	name string,
	installToken string,
) (*models.ConnectorWithInstallTokenResponse, error) {
	payload := &models.ConnectorWithInstallTokenRequest{
		Connector: models.Connector{
			Name:                     name,
			BuiltInSshServiceEnabled: true,
		},
		InstallToken: installToken,
	}

	var reply models.ConnectorWithInstallTokenResponse
	err := a.Request(http.MethodPost, "connector/create_with_token", &reply, payload, true)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// ListConnectors lists an organization's connectors (v2)
func (a *Border0API) ListConnectors(ctx context.Context) ([]models.Connector, error) {
	var connectorList models.ConnectorList
	err := a.Request(http.MethodGet, "connectors", &connectorList, nil, true)
	if err != nil {
		return nil, err
	}
	return connectorList.List, nil
}

// CreateToken creates a new border0 admin token (api key)
func (a *Border0API) CreateToken(ctx context.Context, name string, role string, expiresAt *time.Time) (*models.Token, error) {
	payload := &models.Token{Name: name, Role: role}
	if expiresAt != nil {
		payload.ExpiresAt = expiresAt.Unix()
	}

	var tk models.Token
	err := a.Request(http.MethodPost, "organizations/tokens", &tk, payload, true)
	if err != nil {
		return nil, err
	}

	return &tk, nil
}

// CreateConnectorToken creates a new border0 connector token
func (a *Border0API) CreateConnectorToken(ctx context.Context, connectorId string, name string, expiresAt *time.Time) (*models.ConnectorToken, error) {
	payload := &models.ConnectorTokenRequest{ConnectorId: connectorId, Name: name}
	if expiresAt != nil {
		payload.ExpiresAt = expiresAt.Unix()
	}

	var tk models.ConnectorToken
	err := a.Request(http.MethodPost, "connector/token", &tk, payload, true)
	if err != nil {
		return nil, err
	}

	return &tk, nil
}

// GetDefaultPluginConfiguration returns the default configuration for a given plugin type.
func (a *Border0API) GetDefaultPluginConfiguration(ctx context.Context, pluginType string) (*connector.PluginConfiguration, error) {
	var plugin *models.ConnectorPlugin
	err := a.Request(http.MethodGet, fmt.Sprintf("connector/plugins/defaults/%s", pluginType), &plugin, nil, true)
	if err != nil {
		return nil, err
	}
	return &plugin.Configuration, nil
}

// CreatePlugin creates a new connector plugin.
func (a *Border0API) CreatePlugin(
	ctx context.Context,
	connectorId string,
	enabled bool,
	pluginType string,
	pluginConfiguration *connector.PluginConfiguration,
) (*models.ConnectorPlugin, error) {
	payload := &models.ConnectorPluginRequest{
		ConnectorId:   connectorId,
		Enabled:       enabled,
		PluginType:    pluginType,
		Configuration: pluginConfiguration,
	}
	var plugin *models.ConnectorPlugin
	err := a.Request(http.MethodPost, "connector/plugins", &plugin, payload, true)
	if err != nil {
		return nil, err
	}
	return plugin, nil
}

func (a *Border0API) GetPolicyByName(ctx context.Context, name string) (*models.Policy, error) {
	url := fmt.Sprintf("policies/find?name=%s", name)

	var policy *models.Policy
	err := a.Request("GET", url, &policy, nil, true)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func (a *Border0API) GetPoliciesBySocketID(socketID string) ([]models.Policy, error) {
	url := fmt.Sprintf("policies?socket_id=%s", socketID)

	var policies []models.Policy
	err := a.Request("GET", url, &policies, nil, true)
	if err != nil {
		return nil, err
	}

	return policies, nil
}

func (a *Border0API) RefreshAccessToken() (*models.Credentials, error) {
	if a.Credentials == nil {
		return nil, fmt.Errorf("no credentials found")
	}

	if !a.Credentials.ShouldRefresh() {
		return nil, fmt.Errorf("token is not valid to refresh")
	}

	loginRefresh := models.LoginRefresh{}
	res := models.TokenForm{}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	err := a.Request(http.MethodPost, "login/refresh", &res, loginRefresh, true)
	if err != nil {
		return nil, err
	}

	// create dir if not exists
	configPath := filepath.Dir(tokenfile())
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.Mkdir(configPath, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory %s : %s", configPath, err)
		}
	}

	f, err := os.Create(tokenfile())
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(tokenfile(), 0600); err != nil {
		return nil, err
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s\n", res.Token))
	if err != nil {
		return nil, err
	}

	return models.NewCredentials(res.Token, models.CredentialsTypeUser), nil
}

func (a *Border0API) StartRefreshAccessTokenJob(ctx context.Context) {
	if a.Credentials == nil {
		token, err := getToken()
		if err != nil {
			fmt.Println("no credentials found:", err)
			return
		}

		a.Credentials = token
	}

	if !a.Credentials.ShouldRefresh() {
		return
	}

	onceBody := func() {
		g, ctx := errgroup.WithContext(ctx)
		g.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(1 * time.Hour):
					token, err := a.RefreshAccessToken()
					if err != nil {
						if err.Error() == "token is not valid to refresh" {
							return err
						}

						fmt.Println("failed to refresh token:", err)
					} else {
						func() {
							a.mutex.Lock()
							defer a.mutex.Unlock()
							a.Credentials = token
						}()
					}
				}
			}
		})

		// Run the error group in the background
		go func() {
			if err := g.Wait(); err != nil {
				fmt.Println(err)
			}
		}()
	}

	once.Do(onceBody)
}

func (a *Border0API) SignSSHKey(ctx context.Context, socketID string, key []byte) (string, string, error) {
	newCsr := &models.SshCsr{
		SSHPublicKey: strings.TrimRight(string(key), "\n"),
	}

	url := fmt.Sprintf("socket/%s/signkey", socketID)

	var cert *models.SshCsr
	err := a.Request("POST", url, &cert, newCsr, true)
	if err != nil {
		return "", "", err
	}

	if cert.SSHSignedCert == "" {
		return "", "", fmt.Errorf("error: Unable to get signed key from Server")
	}

	return cert.SSHSignedCert, cert.HostKey, nil
}

func (a *Border0API) GetUserID() (string, error) {
	if a.Credentials == nil || (a.Credentials != nil && a.Credentials.AccessToken == "") {
		token, _ := getToken()
		a.Credentials = token
	}

	token, _ := jwt.Parse(a.Credentials.AccessToken, nil)
	if token == nil {
		return "", fmt.Errorf("failed to parse token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	tokenUserId, ok := claims["user_id"]
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	tokenUserIdStr, ok := tokenUserId.(string)
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	return strings.ReplaceAll(tokenUserIdStr, "-", ""), nil
}

func (a *Border0API) Evaluate(ctx context.Context, socket *models.Socket, clientIP, userEmail, sessionKey string) (allowedActions []string, info map[string][]string, err error) {
	if socket == nil {
		err = fmt.Errorf("socket is nil")
		return
	}

	if clientIP == "" || userEmail == "" || sessionKey == "" {
		err = fmt.Errorf("metadata is invalid")
		return
	}

	clientIP, _, err = net.SplitHostPort(clientIP)
	if err != nil {
		err = fmt.Errorf("failed to parse client ip: %w", err)
		return
	}

	evaluateRequest := &models.EvaluatePolicyRequest{
		ClientIP:   clientIP,
		UserEmail:  userEmail,
		SessionKey: sessionKey,
	}

	url := fmt.Sprintf("socket/%s/evaluate", socket.SocketID)
	var evaluateResponse *models.EvaluatePolicyResponse

	if err = a.Request("POST", url, &evaluateResponse, evaluateRequest, true); err != nil {
		err = fmt.Errorf("evaluate request failed: %w", err)
		return
	}

	for app, actions := range evaluateResponse.Actions {
		if strings.EqualFold(socket.SocketType, app) || app == "*" {
			for _, action := range actions {
				allowedActions = append(allowedActions, strings.ToLower(action))
			}
		}
	}

	return
}

func (a *Border0API) UpdateSession(update models.SessionUpdate) (err error) {
	if update.Socket == nil {
		err = fmt.Errorf("socket is nil")
		return
	}

	evaluateRequest := &models.UpdateSessionRequest{
		SessionKey: update.SessionKey,
		UserData:   update.UserData,
	}

	url := fmt.Sprintf("socket/%s/update_session", update.Socket.SocketID)

	if err = a.Request("POST", url, nil, evaluateRequest, true); err != nil {
		err = fmt.Errorf("update session request failed: %w", err)
		return
	}

	return
}

func (a *Border0API) SignSshOrgCertificate(ctx context.Context, socketID, sessionID, userEmail string, ticket, publicKey []byte) ([]byte, error) {
	signSshOrgCertificateRequest := &models.SignSshOrgCertificateRequest{
		SocketID:   socketID,
		SessionKey: sessionID,
		UserEmail:  userEmail,
		Ticket:     base64.StdEncoding.EncodeToString(ticket),
		PublicKey:  string(publicKey),
	}

	var signSshOrgCertificateResponse models.SignSshOrgCertificateResponse
	if err := a.Request("POST", "organizations/sign_ssh_certificate", &signSshOrgCertificateResponse, signSshOrgCertificateRequest, true); err != nil {
		return nil, fmt.Errorf("sign ssh certificate request failed: %w", err)
	}

	return []byte(signSshOrgCertificateResponse.Certificate), nil
}

func (a *Border0API) UploadRecording(content []byte, socketID, sessionKey, recordingID string) error {
	jsonData, err := json.Marshal(struct {
		RecordingId string `json:"recording_id"`
	}{
		RecordingId: recordingID,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	var requestBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&requestBody)

	err = multipartWriter.WriteField("json_data", string(jsonData))
	if err != nil {
		return fmt.Errorf("failed to write json_data field: %w", err)
	}

	filePart, err := multipartWriter.CreateFormFile("file", recordingID)
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}
	_, err = io.Copy(filePart, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("failed to copy file part: %w", err)
	}

	multipartWriter.Close()

	if err := a.RequestAny("POST", fmt.Sprintf("session/%s/%s/upload_recording", socketID, sessionKey), nil, &requestBody, multipartWriter.FormDataContentType(), true); err != nil {
		return fmt.Errorf("upload recording request failed: %w", err)
	}

	return nil
}

func (a *Border0API) ServerOrgCertificate(ctx context.Context, name string, csr []byte) ([]byte, error) {
	jsonData := struct {
		Name                      string `json:"name"`
		CertificateSigningRequest string `json:"csr"`
	}{
		CertificateSigningRequest: string(csr),
		Name:                      name,
	}

	var signSshOrgCertificateResponse models.SignSshOrgCertificateResponse
	if err := a.Request("POST", "organizations/sign_server_certificate", &signSshOrgCertificateResponse, jsonData, true); err != nil {
		return nil, fmt.Errorf("sign server certificate request failed: %w", err)
	}

	return []byte(signSshOrgCertificateResponse.Certificate), nil
}

func (a *Border0API) Whoami(ctx context.Context) (map[string]any, error) {
	m := map[string]any{}

	err := a.Request(http.MethodGet, "iam/whoami", &m, nil, true)
	if err != nil {
		return nil, err
	}

	return m, nil
}

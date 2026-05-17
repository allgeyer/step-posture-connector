package soti

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/allgeyer/step-posture-connector/internal/shared"
)

// Provider implements the posture-connector Provider interface for SOTI MobileControl.
type Provider struct{}

// Client holds API configuration, the current bearer token and its expiry.
type Client struct {
	baseURL      string // e.g. https://tenant.mobicontrolcloud.com/MobiControl
	clientID     string
	clientSecret string
	username     string
	password     string
	timeout      time.Duration
	token        sotiAuthToken
	tokenExpiry  *time.Time
}

// sotiAuthToken represents the JSON body returned by POST /api/token.
type sotiAuthToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// sotiDevice represents the fields we care about inside a SOTI device search result.
type sotiDevice struct {
	DeviceID     string `json:"DeviceId"`
	DeviceName   string `json:"DeviceName"`
	SerialNumber string `json:"SerialNumber"`
	Path         string `json:"Path"` // group path, e.g. //All Devices/GroupName
}

// sotiDeviceSearchResponse is the top-level wrapper returned by GET /api/devices/search.
type sotiDeviceSearchResponse struct {
	Devices []sotiDevice `json:"value"` // OData-style array key used by SOTI v2 API
}

// sotiGroupMember holds device membership info from GET /api/deviceGroups/{groupPath}/devices.
type sotiGroupMember struct {
	DeviceID string `json:"DeviceId"`
}

var (
	client   Client
	validate *validator.Validate
	config   map[string]interface{}
)

// Bootstrap sets up and validates configuration, then performs a test auth.
// Environment variables expected:
//
//	SOTI_BASE_URL      – e.g. https://tenant.mobicontrolcloud.com/MobiControl
//	SOTI_CLIENT_ID     – API client ID
//	SOTI_CLIENT_SECRET – API client secret
//	SOTI_USERNAME      – MobiControl administrator username
//	SOTI_PASSWORD      – MobiControl administrator password
//	SOTI_DEVICE_GROUP  – (optional) device group path to check membership against
//	SOTI_DEVICE_ENRICH – (optional) "1" to include device details in the response
//	TIMEOUT            – (optional) HTTP timeout in seconds (default 10)
func (p Provider) Bootstrap() error {
	validate = validator.New(validator.WithRequiredStructEnabled())

	config = map[string]interface{}{
		"SOTI_BASE_URL":      os.Getenv("SOTI_BASE_URL"),
		"SOTI_CLIENT_ID":     os.Getenv("SOTI_CLIENT_ID"),
		"SOTI_CLIENT_SECRET": os.Getenv("SOTI_CLIENT_SECRET"),
		"SOTI_USERNAME":      os.Getenv("SOTI_USERNAME"),
		"SOTI_PASSWORD":      os.Getenv("SOTI_PASSWORD"),
		"SOTI_DEVICE_GROUP":  os.Getenv("SOTI_DEVICE_GROUP"),
		"SOTI_DEVICE_ENRICH": os.Getenv("SOTI_DEVICE_ENRICH"),
		"TIMEOUT":            os.Getenv("TIMEOUT"),
	}

	rules := map[string]interface{}{
		"SOTI_BASE_URL":      "required,url",
		"SOTI_CLIENT_ID":     "required",
		"SOTI_CLIENT_SECRET": "required",
		"SOTI_USERNAME":      "required",
		"SOTI_PASSWORD":      "required",
		"SOTI_DEVICE_GROUP":  "omitempty",
		"SOTI_DEVICE_ENRICH": "omitempty,oneof=0 1",
		"TIMEOUT":            "omitempty,number,max=2",
	}

	if errs := validate.ValidateMap(config, rules); len(errs) > 0 {
		return fmt.Errorf("SOTI failed to bootstrap due to invalid config: %s", errs)
	}

	var timeout time.Duration
	if t, err := strconv.ParseInt(config["TIMEOUT"].(string), 10, 32); err != nil {
		timeout = 10 * time.Second
	} else {
		timeout = time.Duration(t) * time.Second
	}

	shared.WriteLog(fmt.Sprintf("SOTI timeout set as %s", timeout), 1, 0)

	client = Client{
		baseURL:      config["SOTI_BASE_URL"].(string),
		clientID:     config["SOTI_CLIENT_ID"].(string),
		clientSecret: config["SOTI_CLIENT_SECRET"].(string),
		username:     config["SOTI_USERNAME"].(string),
		password:     config["SOTI_PASSWORD"].(string),
		timeout:      timeout,
	}

	if err := client.refreshAuthToken(); err != nil {
		return fmt.Errorf("failed to authenticate to SOTI API: %s", err)
	}

	shared.WriteLog("SOTI successfully bootstrapped and ready", 0, 0)
	return nil
}

// Handler looks up a device by its serial number (PermanentIdentifier) and optionally
// verifies that it is a member of the configured device group.
//
// handlerMode is ignored for SOTI (there is a single unified device endpoint); pass ""
// or "device" for forward-compatibility.
func (p Provider) Handler(handlerMode string, stepInputData shared.StepAttestationRequestData) (shared.StepResponseData, error) {
	deviceGroup, _ := config["SOTI_DEVICE_GROUP"].(string)
	enrich, _ := strconv.ParseBool(config["SOTI_DEVICE_ENRICH"].(string))

	// Validate the serial number passed in from step-ca.
	if err := validate.Var(stepInputData.AttestationData.PermanentIdentifier, "required,alphanum,min=8,max=14"); err != nil {
		return shared.StepResponseData{Allow: false},
			fmt.Errorf("serial number did not pass validation: %s", err)
	}

	serial := stepInputData.AttestationData.PermanentIdentifier

	// -------------------------------------------------------------------
	// 1. Search for the device by serial number.
	// -------------------------------------------------------------------
	// SOTI search endpoint: GET /api/devices/search?filter=SerialNumber='<serial>'
	searchPath := fmt.Sprintf("/api/devices/search?filter=SerialNumber%%3D%%27%s%%27", url.QueryEscape(serial))
	body, err := client.doGet(searchPath)
	if err != nil {
		if err.Error() == "404" {
			return shared.StepResponseData{Allow: false},
				fmt.Errorf("serial number not found/enrolled in SOTI (404 on %q)", searchPath)
		}
		return shared.StepResponseData{Allow: false},
			fmt.Errorf("error communicating with SOTI API: %s", err)
	}

	// The SOTI v2 API wraps results in { "value": [...] }
	var searchResp sotiDeviceSearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		// Fallback: try parsing as a plain array (some SOTI versions omit the wrapper).
		var devices []sotiDevice
		if err2 := json.Unmarshal(body, &devices); err2 != nil {
			return shared.StepResponseData{Allow: false},
				fmt.Errorf("error unmarshalling SOTI device search JSON: %s", err)
		}
		searchResp.Devices = devices
	}

	if len(searchResp.Devices) == 0 {
		return shared.StepResponseData{Allow: false},
			fmt.Errorf("device with serial number %q not found in SOTI", serial)
	}

	device := searchResp.Devices[0]
	shared.WriteLog(
		fmt.Sprintf("SOTI device %q (ID: %s) matched for serial number %s",
			device.DeviceName, device.DeviceID, serial),
		1, 0,
	)

	// -------------------------------------------------------------------
	// 2. Optionally verify group membership.
	// -------------------------------------------------------------------
	var groupMatch bool
	if deviceGroup != "" {
		groupMatch, err = client.isDeviceInGroup(device.DeviceID, deviceGroup)
		if err != nil {
			return shared.StepResponseData{Allow: false},
				fmt.Errorf("error checking SOTI group membership: %s", err)
		}
		if !groupMatch {
			return shared.StepResponseData{Allow: false},
				fmt.Errorf("%s is not a member of group %q", serial, deviceGroup)
		}
		shared.WriteLog(
			fmt.Sprintf("Device %s is a member of group %q", device.DeviceID, deviceGroup),
			1, 0,
		)
	}

	// -------------------------------------------------------------------
	// 3. Build the response.
	// -------------------------------------------------------------------
	if enrich {
		enrichData := map[string]interface{}{
			"device": map[string]interface{}{
				"device_id":     device.DeviceID,
				"name":          device.DeviceName,
				"serial_number": device.SerialNumber,
				"path":          device.Path,
			},
		}
		return shared.StepResponseData{Allow: true, Data: enrichData}, nil
	}

	return shared.StepResponseData{Allow: true}, nil
}

// -------------------------------------------------------------------
// Private helpers
// -------------------------------------------------------------------

// refreshAuthToken obtains or reuses a bearer token from SOTI's OAuth2 endpoint.
//
// SOTI MobileControl uses the Resource Owner Password Credentials grant:
//
//	POST /MobiControl/api/token
//	Authorization: Basic base64(clientID:clientSecret)
//	Content-Type: application/x-www-form-urlencoded
//	Body: grant_type=password&username=<user>&password=<pass>
func (c *Client) refreshAuthToken() error {
	if c.tokenExpiry != nil && c.tokenExpiry.After(time.Now().Add(30*time.Second)) {
		shared.WriteLog(
			fmt.Sprintf("SOTI auth token is valid until %s – no need to refresh", c.tokenExpiry),
			1, 0,
		)
		return nil
	}

	httpClient := &http.Client{Timeout: c.timeout}

	form := url.Values{
		"grant_type": {"password"},
		"username":   {c.username},
		"password":   {c.password},
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/token", c.baseURL),
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed (%d): %s", resp.StatusCode, b)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var authToken sotiAuthToken
	if err := json.Unmarshal(b, &authToken); err != nil {
		return fmt.Errorf("error unmarshalling SOTI token JSON: %s", err)
	}

	expiry := time.Now().Add(time.Duration(authToken.ExpiresIn) * time.Second)
	c.tokenExpiry = &expiry
	c.token = authToken

	shared.WriteLog(
		fmt.Sprintf("Successfully refreshed SOTI API token. Will expire %s", expiry),
		1, 0,
	)
	return nil
}

// doGet performs an authenticated GET request against the SOTI API and returns the body.
func (c *Client) doGet(uri string) ([]byte, error) {
	shared.WriteLog(fmt.Sprintf("SOTI GET %s%s", c.baseURL, uri), 2, 0)

	if err := c.refreshAuthToken(); err != nil {
		return nil, err
	}

	httpClient := &http.Client{Timeout: c.timeout}

	req, err := http.NewRequest("GET", c.baseURL+uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token.AccessToken))

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d on GET (%s%s)", resp.StatusCode, c.baseURL, uri)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	return body, nil
}

// isDeviceInGroup checks whether deviceID is a member of the given SOTI device group.
//
// SOTI represents groups as hierarchical paths (e.g. "//All Devices/Compliant").
// We fetch the group's device list and scan for the device ID.
//
// Endpoint: GET /api/deviceGroups/{encodedPath}/devices
func (c *Client) isDeviceInGroup(deviceID, groupPath string) (bool, error) {
	encodedPath := url.PathEscape(groupPath)
	uri := fmt.Sprintf("/api/deviceGroups/%s/devices", encodedPath)

	body, err := c.doGet(uri)
	if err != nil {
		return false, err
	}

	// Try OData-wrapped array first, fall back to plain array.
	var members []sotiGroupMember
	var wrapper struct {
		Value []sotiGroupMember `json:"value"`
	}
	if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Value) > 0 {
		members = wrapper.Value
	} else if err := json.Unmarshal(body, &members); err != nil {
		return false, fmt.Errorf("error unmarshalling SOTI group members JSON: %s", err)
	}

	for _, m := range members {
		if m.DeviceID == deviceID {
			return true, nil
		}
	}
	return false, nil
}

//
// Copyright (c) 2021 Cisco Systems, Inc and its affiliates
// All Rights reserved
//
package msxsecurity

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/allegro/bigcache"
)

type User struct {
	Permissions     []string `json:"permissions,omitempty"`
	TenantID        string   `json:"tenant_id,omitempty"`
	AssignedTenants []string `json:"assigned_tenants,omitempty"`
	Active          bool     `json:"active,omitempty"`
}

// Config represents the config for performing Security on the targeted MSX environment.
type Config struct {
	SsoURL       string      // URL to User Management Service in your MSX environment.
	Cache        Cache       // Cache to use for local caching.
	TLS          *tls.Config // TLS config to use on outgoing client.
	ClientID     string      // Credential to use when speaking to MSX.
	ClientSecret string      // Credential to use when speaking to MSX.
}

// Cache represents a cache for storing token permissions locally to speed up security actions.
type Cache struct {
	Enabled         bool
	LifetimeSeconds int
}

type MsxSecurity struct {
	Cfg    Config
	Cache  *bigcache.BigCache
	Client *http.Client
}

// HasPermission will return true or false given an HTTP request and target permission.
func (m *MsxSecurity) HasPermission(r *http.Request, perm string) (bool, User) {
	token := r.Header.Get("Authorization")
	if len(token) == 0 {
		return false, User{}
	}

	tokenStrings := strings.Split(token, " ")
	if len(tokenStrings) > 2 {
		token = tokenStrings[1]
	}

	return m.checkToken(token, perm)
}

func (m *MsxSecurity) checkToken(token string, perm string) (bool, User) {
	user := User{}
	// Check to see if token exists in the cache.
	if m.Cfg.Cache.Enabled {
		plist, err := m.Cache.Get(string(token))
		if err == nil {
			err := json.Unmarshal(plist, &user)
			if err == nil {
				if checkperms(user.Permissions, perm) {
					return true, user
				}
				return false, user
			}
		}
	}

	endpoint := fmt.Sprintf("%s/v2/check_token?token_type_hint=access_token", m.Cfg.SsoURL)

	// token passed in via body
	var formData = make(url.Values)
	formData.Set("token", token)
	var encodedFormData = formData.Encode()

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(encodedFormData))
	if err != nil {
		log.Printf("ERROR: %s", err.Error())
		return false, user
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")
	req.Header.Add("Content-Length", strconv.Itoa(len(encodedFormData)))
	req.SetBasicAuth(m.Cfg.ClientID, m.Cfg.ClientSecret)
	resp, err := m.Client.Do(req)
	if err != nil {
		log.Printf("ERROR: Making request to IDM: %s", err.Error())
		return false, user
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: Request to IDM not successful got HTTP %d", resp.StatusCode)
		return false, user
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: Reading response body: %s", err.Error())
		return false, user
	}
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Printf("ERROR: Unmarshalling body: %s , Err: %s", err.Error())
		return false, user
	}
	if checkperms(user.Permissions, perm) {
		if m.Cfg.Cache.Enabled {
			m.Cache.Set(string(token), body)
		}
		return true, user
	}
	return false, user
}

// NewMsxSecurity returns an MsxSecurity with default config set.
func NewMsxSecurity(cfg Config) *MsxSecurity {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg.TLS}}
	if cfg.Cache.Enabled {
		bccfg := bigcache.DefaultConfig(time.Duration(cfg.Cache.LifetimeSeconds) * time.Second)
		bccfg.MaxEntriesInWindow = 10 * cfg.Cache.LifetimeSeconds
		bccfg.MaxEntrySize = 5000
		bccfg.HardMaxCacheSize = 128
		bc, err := bigcache.NewBigCache(bccfg)
		if err != nil {
			log.Printf("Could not init cache: %s", err.Error())
		}
		return &MsxSecurity{Cache: bc, Cfg: cfg, Client: c}
	}
	return &MsxSecurity{Cfg: cfg, Client: c}
}

// DefaultMsxSecurityConfig returns a default config.
// Note this default is not secure and should not be used in a production environment.
func DefaultMsxSecurityConfig() Config {
	return Config{
		SsoURL: "http://localhost:9103/idm",
		Cache: Cache{
			Enabled: false,
		},
		TLS: &tls.Config{InsecureSkipVerify: true},
	}
}

func checkperms(perms []string, perm string) bool {
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

package mfa

import (
	"log"
	"net/http"
)

const DUO = "duo"
const PING = "pingone"

type duoConfig struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ApiHost      string `json:"api_host"`
	AuthUrl      string `json:"auth_url"`
	RedirectUrl  string `json:"redirect_url"`
	FailOpen     bool   `json:"fail_open"`
}

type pingConfig struct {
	IdpAccountId string `json:"idp_account_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"aud"`
	AuthUrl      string `json:"auth_url"`
	ReturnUrl    string `json:"return_url"`
}

type mfaConfig struct {
	Duo  duoConfig  `json:"duo"`
	Ping pingConfig `json:"ping"`
}

type Config struct {
	MfaConfig mfaConfig `json:"mfa"`
}

func logMessage(message string, level string) {
	switch level {
	case "debug":
		log.Printf("%s", message)
	case "info":
		log.Printf("%s", message)
	default:
		log.Printf("%s", message)
	}
}

type provider interface {
	Init(*http.Request, http.ResponseWriter)
	SendAuthenticationRedirect(*http.Request, http.ResponseWriter, string) error
	ProcessAuthenticationResult(*http.Request, http.ResponseWriter) error
}

func GetProvider(name string) provider {
	var provider provider
	switch name {
	case DUO:
		provider = &duo{}
	case PING:
		provider = &ping{}
	}

	return provider
}

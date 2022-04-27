package mfa

import (
	"encoding/json"
	"fmt"
	"github.com/juju/errors"
	"io/ioutil"
	jwt2 "jwt"
	"net/http"
	"net/url"
	"os"
	"rand"
	"time"
)

const ClientId = "DUO_CLIENT_ID"
const ClientSecret = "DUO_CLIENT_SECRET"
const ApiHost = "DUO_API_HOST"
const AuthUrl = "DUO_AUTH_URL"
const RedirectUrl = "DUO_REDIRECT_URL"

type Duo struct {
	clientId     string
	clientSecret string
	apiHost      string
	authUrl      string
	redirectUrl  string
	failOpen     bool
	oidcState    string
}

func (d *Duo) IsDuoHealthy() bool {
	healthUrl := fmt.Sprintf("%s%s%s", "https://", d.apiHost, "/oauth/v1/health_check")
	form := url.Values{}
	form.Add("client_id", d.clientId)
	form.Add("client_assertion", d.generateHealthToken())
	resp, err := http.PostForm(healthUrl, form)

	if err != nil {
		return false
	}

	if resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		logMessage(fmt.Sprintf("Duo Health Response body %s", body), "info")
		var data interface{}
		if err = json.Unmarshal(body, &data); err != nil {
			logMessage(fmt.Sprintf("Parsing Health Response %s", err.Error()), "info")
			return false
		}
		status := data.(map[string]interface{})["stat"]
		statusString := status.(string)
		logMessage(fmt.Sprintf("Duo Health Status %s", status), "info")
		if statusString == "OK" {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

func (d *Duo) generateAuthRedirectUrl(subject string, r *http.Request) (*url.URL, error) {
	authUrl := fmt.Sprintf("%s%s%s", "https://", d.apiHost, "/oauth/v1/authorize")
	loc, err := url.Parse(authUrl)

	if err != nil {
		errors.Trace(err)
		return nil, err
	}

	query := loc.Query()
	query.Set("response_type", "code")
	query.Set("client_id", d.clientId)
	query.Set("request", d.generateAuthToken(subject, r))
	loc.RawQuery = query.Encode()
	return loc, nil
}

func (d *Duo) generateAuthToken(subject string, r *http.Request) string {
	query := url.Values{}
	query.Set("origDest", fmt.Sprintf("%s%s%s", "https://", r.Host, r.URL.String()))
	origDest := query.Encode()
	d.oidcState = rand.String(30)

	claims := jwt2.NewClaim()
	claims.Set("response_type", "code")
	claims.Set("scope", "openid")
	claims.Set("client_id", d.clientId)
	claims.Set("redirect_uri", fmt.Sprintf("%s%s%s", d.redirectUrl, "?", origDest))
	//claims.Set("redirect_uri", d.redirectUrl)
	claims.Set("state", d.oidcState)
	claims.Set("duo_uname", subject)
	claims.SetTime("exp", time.Now().Add(5*time.Minute))

	algorithm := jwt2.HmacSha512(d.clientSecret)
	signedToken, err := algorithm.Encode(claims)

	if err != nil {
		errors.Wrap(err, errors.New("Failed to sign claims"))
		logMessage(fmt.Sprintf("Failed signing JWT Auth token %s", err.Error()), "error")
		return ""
	}

	logMessage(fmt.Sprintf("Generate Duo Auth Token %s", string(signedToken)), "info")

	return signedToken
}

func (d *Duo) generateHealthToken() string {
	audienceUrl := fmt.Sprintf("%s%s%s", "https://", d.apiHost, "/oauth/v1/health_check")

	claims := jwt2.NewClaim()
	claims.SetIssuer(d.clientId)
	claims.SetSubject(d.clientId)
	claims.SetAudience(audienceUrl)
	claims.Set("jti", rand.String(30))
	claims.SetTime("iat", time.Now())
	claims.SetTime("exp", time.Now().Add(5*time.Minute))

	algorithm := jwt2.HmacSha512(d.clientSecret)
	signedToken, err := algorithm.Encode(claims)

	if err != nil {
		errors.Wrap(err, errors.New("Failed to sign JWT token"))
		logMessage(fmt.Sprintf("Failed signing JWT token %s", err.Error()), "error")
		return ""
	}

	logMessage(fmt.Sprintf("Generate Duo Health Token %s", signedToken), "info")
	return signedToken
}

func (d *Duo) configFromEnvironment() (duoConfig, error) {
	var duoConfig duoConfig

	duoConfig.ClientId = os.Getenv(ClientId)
	duoConfig.ClientSecret = os.Getenv(ClientSecret)
	duoConfig.ApiHost = os.Getenv(ApiHost)
	duoConfig.AuthUrl = os.Getenv(AuthUrl)
	duoConfig.RedirectUrl = os.Getenv(RedirectUrl)

	return duoConfig, nil
}

func (d *Duo) parseConfigFile() (duoConfig, error) {
	var duoConfig duoConfig
	var config Config
	var file *os.File
	var err error

	configFile := os.Getenv("CONFIG_FILE")

	if file, err = os.Open(configFile); err != nil {
		errors.Trace(err)
		logMessage(err.Error(), "fatal")
		return duoConfig, err
	}

	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)

	if err != nil {
		logMessage(err.Error(), "error")
		return duoConfig, err
	}

	json.Unmarshal(byteValue, &config)
	return config.MfaConfig.Duo, nil
}

func (d *Duo) Init() error {
	configFile := os.Getenv("CONFIG_FILE")

	var duoConfig duoConfig
	var err error

	if configFile != "" {
		duoConfig, err = d.parseConfigFile()
	} else if os.Getenv(ClientId) != "" {
		duoConfig, err = d.configFromEnvironment()
	} else {
		panic("We need the configuration either in configuration file or as environment variables")
	}

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Error parsing config file %s", err.Error()), "error")
		return err
	}

	d.clientId = duoConfig.ClientId
	d.clientSecret = duoConfig.ClientSecret
	d.apiHost = duoConfig.ApiHost
	d.authUrl = duoConfig.AuthUrl
	d.redirectUrl = duoConfig.RedirectUrl
	d.failOpen = duoConfig.FailOpen
	logMessage(fmt.Sprintf("%v", d), "info")
	return nil
}

func (d *Duo) SendAuthenticationRedirect(r *http.Request, rw http.ResponseWriter, subject string) error {
	if !d.IsDuoHealthy() {
		if !d.failOpen {
			logMessage(fmt.Sprintf("Duo is unhealthy, failOpen is set to false"), "error")
			rw.WriteHeader(http.StatusInternalServerError)
			return errors.New("Duo is unhealthy, failOpen is set to false")
		} else {
			logMessage(fmt.Sprintf("Duo is unhealthy, failOpen is set to true"), "error")
		}
	}

	authUrl, err := d.generateAuthRedirectUrl(subject, r)

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Failed generating Duo Auth redirect url %s", err.Error()), "error")
		rw.WriteHeader(http.StatusInternalServerError)
		return errors.Wrap(err, errors.New("Failed to generate Duo Auth redirect url"))
	}

	logMessage(fmt.Sprintf("Duo Auth Redirect Url %s", authUrl.String()), "info")
	http.Redirect(rw, r, authUrl.String(), http.StatusFound)
	return nil
}

func (d *Duo) ProcessAuthenticationResult(r *http.Request, rw http.ResponseWriter) error {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	logMessage(fmt.Sprintf("code: %s state: %s", code, state), "info")

	return nil
}

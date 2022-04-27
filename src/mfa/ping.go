package mfa

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/juju/errors"
	"html/template"
	"io/ioutil"
	jwt2 "jwt"
	"net/http"
	"net/url"
	"os"
	"rand"
	"time"
)

type ping struct {
	clientSecret string
	idpAccountId string
	returnUrl    string
	authUrl      string
	audience     string
}

func (p *ping) generatePostHtml(subject string, r *http.Request) (bytes.Buffer, http.Cookie, error) {
	jwtToken, cookie, err := p.generateAuthToken(subject, r)
	var rv bytes.Buffer

	if err != nil {
		return rv, http.Cookie{}, err
	}

	const html = `
                  <html>
                       <body>
                          <form method="POST" action="{{.URL}}" id="pingForm">
                              <input type="hidden" name="idp_account_id" value="{{.IdpAccountId}}"/>
                              <input type="hidden" name="ppm_request" value="{{.PpmRequest}}"/>
                              <input type="submit"  value="submit" id="submitButton"/>
                          </form>
                          <script>
                              document.getElementById("submitButton").style.visibility="hidden";
                              document.getElementById("pingForm").submit();
                          </script>
                       </body>
                    </html>
     `
	templ, err := template.New("ping-post-form").Parse(html)

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Failed to parse html template %s", err.Error()), "error")
		return rv, http.Cookie{}, err
	}

	htmlData := struct {
		URL          string
		IdpAccountId string
		PpmRequest   string
	}{
		URL:          p.authUrl,
		IdpAccountId: p.idpAccountId,
		PpmRequest:   jwtToken,
	}

	err = templ.Execute(&rv, htmlData)

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Failed to execute template %s", err.Error()), "error")
		return rv, http.Cookie{}, err
	}

	return rv, cookie, nil
}

func (p *ping) generateAuthToken(subject string, r *http.Request) (string, http.Cookie, error) {
	hash, cookie, err := p.WriteStateCookie(r)

	claims := jwt2.NewClaim()
	claims.Set("idpAccountId", p.idpAccountId)
	claims.Set("returnUrl", p.returnUrl)
	claims.Set("nonce", hash)
	claims.Set("sub", subject)
	claims.Set("aud", p.audience)
	claims.SetTime("iat", time.Now())
	claims.SetTime("exp", time.Now().Add(5*time.Minute))

	key, err := base64.StdEncoding.DecodeString(p.clientSecret)

	if err != nil {
		errors.Wrap(err, errors.New("Failed to base64 decode ping secret"))
		logMessage(fmt.Sprintf("Failed to base64 decode ping secret %s", err.Error()), "error")
		return "", http.Cookie{}, err
	}

	algorithm := jwt2.HmacSha256(string(key))
	signedToken, err := algorithm.Encode(claims)

	if err != nil {
		errors.Wrap(err, errors.New("Failed signing JWT Auth token"))
		logMessage(fmt.Sprintf("Failed signing JWT Auth token %s", err.Error()), "error")
		return "", http.Cookie{}, err
	}

	logMessage(fmt.Sprintf("Generate Ping Auth Token %s", string(signedToken)), "info")

	return signedToken, cookie, nil
}

func (p *ping) parseConfigFile() (pingConfig, error) {
	var pingConfig pingConfig
	var config Config
	var file *os.File
	var err error

	configFile := os.Getenv("CONFIG_FILE")

	if file, err = os.Open(configFile); err != nil {
		errors.Trace(err)
		logMessage(err.Error(), "fatal")
		return pingConfig, err
	}

	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)

	if err != nil {
		logMessage(err.Error(), "error")
		return pingConfig, err
	}

	json.Unmarshal(byteValue, &config)
	return config.MfaConfig.Ping, nil
}

func (p *ping) Init() error {
	pingConfig, err := p.parseConfigFile()

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Error parsing config file %s", err.Error()), "error")
		return err
	}

	p.clientSecret = pingConfig.ClientSecret
	p.idpAccountId = pingConfig.IdpAccountId
	p.returnUrl = pingConfig.ReturnUrl
	p.audience = pingConfig.Audience
	p.authUrl = pingConfig.AuthUrl

	return nil
}

func (p *ping) WriteStateCookie(r *http.Request) (string, http.Cookie, error) {
	type stateObject struct {
		nonce       string `json:"nonce"`
		destination string `json:"destination"`
	}

	origDest := fmt.Sprintf("%s%s%s", "https://", r.Host, r.URL.String())
	state := stateObject{
		destination: origDest,
		nonce:       rand.String(30),
	}

	bytes, err := json.Marshal(state)

	if err != nil {
		logMessage(fmt.Sprintf("Failed to encode state object %s", err.Error()), "error")
		return "", http.Cookie{}, err
	}

	logMessage(fmt.Sprintf("Writing cookie with state variable %s", string(bytes)), "debug")
	hash := sha256.New().Sum(bytes)
	logMessage(fmt.Sprintf("sha256 hash of the state object %s", hash), "debug")

	b64state := base64.RawStdEncoding.EncodeToString(bytes)

	cookie := http.Cookie{
		Name:     "maverics_nonce",
		Value:    string(b64state),
		Domain:   "poddar.club",
		Expires:  time.Time{},
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return string(hash), cookie, nil
}

func (p *ping) SendAuthenticationRedirect(r *http.Request, rw http.ResponseWriter, subject string) error {
	rv, cookie, err := p.generatePostHtml(subject, r)

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Failed to generate post html %s", err.Error()), "error")
		rw.WriteHeader(http.StatusInternalServerError)
		return err
	}

	http.SetCookie(rw, &cookie)
	rw.Write(rv.Bytes())
	return nil
}

func (p *ping) decodeValidateJwt(jwtToken string) (*jwt2.Claims, error) {
	key, err := base64.StdEncoding.DecodeString(p.clientSecret)

	if err != nil {
		errors.Wrap(err, errors.New("Failed to base64 decode ping secret"))
		logMessage(fmt.Sprintf("Failed to base64 decode ping secret %s", err.Error()), "error")
		return nil, err
	}

	algorithm := jwt2.HmacSha256(string(key))
	claims, err := algorithm.DecodeAndValidate(jwtToken)

	return claims, err
}

func (p *ping) ProcessAuthenticationResult(r *http.Request, rw http.ResponseWriter) error {
	purl, _ := url.Parse(p.returnUrl)

	if r.URL.Path != purl.Path {
		msg := fmt.Sprintf("%s: Unexpected Request, expected: %s", r.URL.Path, purl.Path)
		logMessage(msg, "error")
		rw.WriteHeader(http.StatusNotFound)
		return errors.New(msg)
	}

	logMessage("Received Ping PPM Callback", "debug")

	// The response from Ping is posted as ppm_response parameter
	// We need to first parse the form
	err := r.ParseForm()

	if err != nil {
		msg := fmt.Sprintf("Failed to parse posted form from ping %s", err.Error())
		logMessage(msg, "error")
		rw.WriteHeader(http.StatusInternalServerError)
		return errors.Wrap(err, errors.New(msg))
	}

	jwt := r.Form.Get("ppm_response")

	if jwt == "" {
		msg := fmt.Sprintf("ppm_response not present in the form %v", r.Form)
		logMessage(msg, "error")
		rw.WriteHeader(http.StatusInternalServerError)
		return errors.New(msg)
	}

	logMessage(fmt.Sprintf("Obtained ppm_response as JWT token %s", jwt), "debug")

	claims, err := p.decodeValidateJwt(jwt)

	if err != nil {
		msg := fmt.Sprintf("ppm_response failed JWT validation %s", err.Error())
		logMessage(msg, "error")
		rw.WriteHeader(http.StatusInternalServerError)
		return errors.Wrap(err, errors.New(msg))
	}

	logMessage(fmt.Sprintf("Successfully vaidated JWT token. Claims: %s", *claims), "debug")

	return nil
}

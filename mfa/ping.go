package mfa

import (
	"Maverics/jwt"
	"Maverics/rand"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/juju/errors"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

type ping struct {
	clientSecret string
	idpAccountId string
	returnUrl    string
	authUrl      string
	audience     string
}

func (p *ping) generatePostHtml(subject string, r *http.Request) (bytes.Buffer, error) {
	jwtToken, err := p.generateAuthToken(subject, r)
	var rv bytes.Buffer

	if err != nil {
		return rv, err
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
		return rv, err
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
		return rv, err
	}

	return rv, nil
}

func (p *ping) generateAuthToken(subject string, r *http.Request) (string, error) {
	query := url.Values{}
	query.Set("origDest", fmt.Sprintf("%s%s%s", "https://", r.Host, r.URL.String()))
	origDest := query.Encode()
	nonce := rand.String(30)

	claims := jwt.NewClaim()
	claims.Set("idpAccountId", p.idpAccountId)
	claims.Set("returnUrl", fmt.Sprintf("%s%s%s", p.returnUrl, "?", origDest))
	claims.Set("dst", origDest)
	claims.Set("nonce", nonce)
	claims.Set("sub", subject)
	claims.Set("aud", p.audience)
	claims.SetTime("iat", time.Now())
	claims.SetTime("exp", time.Now().Add(5*time.Minute))

	key, err := base64.StdEncoding.DecodeString(p.clientSecret)

	if err != nil {
		errors.Wrap(err, errors.New("Failed to base64 decode ping secret"))
		logMessage(fmt.Sprintf("Failed to base64 decode ping secret %s", err.Error()), "error")
		return "", err
	}

	algorithm := jwt.HmacSha256(string(key))
	signedToken, err := algorithm.Encode(claims)

	if err != nil {
		errors.Wrap(err, errors.New("Failed signing JWT Auth token"))
		logMessage(fmt.Sprintf("Failed signing JWT Auth token %s", err.Error()), "error")
		return "", err
	}

	logMessage(fmt.Sprintf("Generate Ping Auth Token %s", string(signedToken)), "info")

	return signedToken, nil
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

func (p *ping) Init(r *http.Request, rw http.ResponseWriter) {
	pingConfig, err := p.parseConfigFile()

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Error parsing config file %s", err.Error()), "error")
		rw.WriteHeader(http.StatusInternalServerError)
	}

	p.clientSecret = pingConfig.ClientSecret
	p.idpAccountId = pingConfig.IdpAccountId
	p.returnUrl = pingConfig.ReturnUrl
	p.audience = pingConfig.Audience
	p.authUrl = pingConfig.AuthUrl
}

func (p *ping) SendAuthenticationRedirect(r *http.Request, rw http.ResponseWriter, subject string) {
	rv, err := p.generatePostHtml(subject, r)

	if err != nil {
		errors.Trace(err)
		logMessage(fmt.Sprintf("Failed to generate post html %s", err.Error()), "error")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Write(rv.Bytes())
}

func (p *ping) ProcessAuthenticationResult(r *http.Request, rw http.ResponseWriter) error {
	return nil
}

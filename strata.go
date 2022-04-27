package main

import (
	"fmt"
	"maverics"
	"maverics/log"
	"maverics/session"
	"mfa"
	"net/http"
	"os"
	"plainid"
	"strconv"
	"strings"
)

type idpType struct {
	name           string
	usernameClaim  string
	givenNameClaim string
	surNameClaim   string
	emailClaim     string
}

func invokePlainId(ag *maverics.AppGateway, req *http.Request, idp idpType) (*plainid.Plainid, error) {
	plainidObj := plainid.GetPlainId()
	username := session.GetString(req, idp.usernameClaim)
	log.Debug("msg", fmt.Sprintf("Found username %s in session", username))

	config := map[string]string{
		"host":          "https://oneauthorize.sandbox.ey.com/api/runtime/token/v4",
		"client_id":     "PJPM8VXGU86DEC5KIW28M",
		"client_secret": "b390bT-tAfoDU@EK%pfRIiTbJQt@CPuEfF@Pvdgd",
		//"entity_id":     "auth0nativetestaccount002@eysi5.com",
		"entity_id": username,
		//"application":   "Capital Edge 5.0",
		"application": ag.Name,
	}

	log.Debug("msg", ag.Name+": Calling Plain ID")
	plainidObj.Init(config)
	err := plainidObj.CallPlainId()

	if err != nil {
		log.Error("msg", "Error when calling Plain ID"+err.Error())
		return plainidObj, err
	}

	log.Debug("msg", ag.Name+": Plain ID response "+plainidObj.StrResponse)
	return plainidObj, nil
}

func findIdp(ag *maverics.AppGateway, req *http.Request) idpType {
	log.Debug("Finding IDP for ", ag.Name)
	idp := idpType{
		name:           "auth0",
		usernameClaim:  "auth0.email",
		givenNameClaim: "auth0.nickname",
		surNameClaim:   "auth0.nickname",
		emailClaim:     "auth0.email",
	}
	return idp
}

func getHttpScheme(req *http.Request) string {
	if req.TLS == nil {
		return "http://"
	} else {
		return "https://"
	}
}

func processPlainId(ag *maverics.AppGateway, req *http.Request, idp idpType) error {
	plainidObj, err := invokePlainId(ag, req, idp)

	if err != nil {
		return err
	}

	primaryIdp := plainidObj.GetIDP(plainid.PrimaryAuthentication)
	mfaProvider := plainidObj.GetIDP(plainid.SecondaryAuthentication)
	userAccess := plainidObj.IsUserAllowedToAccessApplication()
	projectAccount := plainidObj.IsProjectionAccountAuthenticationRequired()
	log.Debug("msg", ag.Name+" Primary Authentication: "+primaryIdp)
	log.Debug("msg", ag.Name+" Secondary Authentication: "+strings.ToLower(mfaProvider))
	log.Debug("msg", ag.Name+" User Access Application: "+strconv.FormatBool(userAccess))
	log.Debug("msg", ag.Name+" User Projection Account: "+projectAccount)

	session.Set(req, "login.mfaProvider", strings.ToLower(mfaProvider))
	session.Set(req, "login."+mfaProvider+".authenticated", "false")
	session.Set(req, "login.projectionEmail", projectAccount)
	session.Set(req, "login.userApplicationAccess", userAccess)
	session.Set(req, "login."+ag.Name+".PlainID_Response", "done")

	return nil
}

func isSecondaryAuthenticationComplete(ag *maverics.AppGateway, req *http.Request,
	rw http.ResponseWriter) bool {
	mfaProvider := session.GetString(req, "login.mfaProvider")

	if mfaProvider == "" {
		return true
	}

	mfaCompleted := session.GetString(req, "login."+mfaProvider+".authenticated")

	if strings.EqualFold(mfaCompleted, "true") {
		return true
	} else {
		if strings.EqualFold(mfaProvider, "duo") {
			username := session.GetString(req, "login.username")
			duo := mfa.GetProvider("duo")
			os.Setenv(mfa.ClientId, "DI24EU4RZU6NJRWSIZ2M")
			os.Setenv(mfa.ClientSecret, "A9eAOSynrXoWchNFeURvTuYveIjS03lkgDLO0LDK")
			os.Setenv(mfa.ApiHost, "api-cb9a9fd4.duosecurity.com")
			os.Setenv(mfa.AuthUrl, "https://api-cb9a9fd4.duosecurity.com/oauth/v1/authorize")
			os.Setenv(mfa.RedirectUrl, "https://maverics-test.poddar.club/duo-handler")
			duo.Init()
			duo.SendAuthenticationRedirect(req, rw, username)
			return false
		} else {
			return true
		}
	}
}

func isAuthenticated(ag *maverics.AppGateway, rw http.ResponseWriter, req *http.Request) bool {
	log.Debug("msg" + " isAuthenticated for " + ag.Name)
	if session.GetString(req, ag.Name+".authenticated") == "true" {
		log.Debug("msg", ag.Name+" authentication completed")
		return true
	} else {
		log.Debug("msg", ag.Name+" authentication not completed")
		return false
	}
}

func authenticate(ag *maverics.AppGateway, rw http.ResponseWriter, req *http.Request) error {
	log.Debug("msg", "Authenticate Enter for application "+ag.Name)
	idp := findIdp(ag, req)
	idpAuthnStatus := session.GetString(req, idp.name+".authenticated")

	if idpAuthnStatus != "true" {
		session.Set(req, "login.idp", idp)
		log.Debug("msg", ag.Name+" primary authentication not complete, redirecting to "+idp.name)
		ag.IDPs[idp.name].CreateRequest().Login(rw, req)
		return nil
	} else {
		log.Debug("msg", ag.Name+" primary authentication complete")
		username := session.GetString(req, idp.usernameClaim)
		session.Set(req, "login.username", username)

		if session.GetString(req, "login."+ag.Name+".PlainID_Response") == "" {
			err := processPlainId(ag, req, idp)

			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				return nil
			}
		}

		userAccess := session.GetString(req, "login.userApplicationAccess")

		if strings.EqualFold(userAccess, "false") {
			rw.WriteHeader(http.StatusForbidden)
			return nil
		} else {
			if isSecondaryAuthenticationComplete(ag, req, rw) {
				session.Set(req, ag.Name+".authenticated", "true")
				url := getHttpScheme(req) + req.Host + req.URL.String()
				log.Debug("msg", "Redirecting to requested URL: "+url)
				http.Redirect(rw, req, url, http.StatusFound)
			}
			return nil
		}
	}
}

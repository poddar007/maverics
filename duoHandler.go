package main

import (
	"maverics"
	"maverics/log"
	"maverics/session"
	"net/http"
)

const mfaProvider = "duo"

func isAuthenticatedDuo(ag *maverics.AppGateway, rw http.ResponseWriter, req *http.Request) bool {
	log.Debug("msg", "isAuthenticatedDuo, returning false")
	return false
}

func authenticateDuo(ag *maverics.AppGateway, rw http.ResponseWriter, req *http.Request) error {
	log.Debug("msg", "authenticateDuo")
	session.Set(req, "login."+mfaProvider+".authenticated", "true")
	originalDestination := req.URL.Query().Get("origDest")
	log.Debug("msg", "authenticateDuo original destination: "+originalDestination)
	http.Redirect(rw, req, originalDestination, http.StatusFound)
	return nil
}

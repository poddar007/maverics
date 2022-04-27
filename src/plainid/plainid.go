package plainid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"maverics/log"
	"net/http"
	"strings"
)

const PrimaryAuthentication = "Primary Authentication"
const SecondaryAuthentication = "Secondary Authentication"

type request struct {
	EntityId               string             `json:"entityId"`
	EntityTypeId           string             `json:"entityTypeId"`
	ClientID               string             `json:"clientId"`
	ClientSecret           string             `json:"clientSecret"`
	IncludeAccessPolicy    bool               `json:"includeAccessPolicy"`
	IncludeIdentity        bool               `json:"includeIdentity"`
	IncludeAssetAttributes bool               `json:"includeAssetAttributes"`
	IncludeContext         bool               `json:"includeContext"`
	ContextData            requestContextData `json:"contextData"`
}

type requestContextData struct {
	Application []string `json:"application"`
}

type responseAction struct {
	Action string `json:"action"`
}

type oneAccess struct {
	Path         string           `json:"path"`
	ResourceType string           `json:"resourceType"`
	Actions      []responseAction `json:"actions"`
}

type allAccess struct {
	Access []oneAccess `json:"access"`
}

type response struct {
	TokenValidity int         `json:"tokenValidity"`
	Response      []allAccess `json:"response"`
}

type Plainid struct {
	clientId               string
	clientSecret           string
	host                   string
	entityId               string
	entityTypeId           string
	application            string
	includeAssetAttributes bool
	includeAccessPolicy    bool
	includeIdentity        bool
	includeContext         bool
	vResponse              response
	StrResponse            string
}

func (p *Plainid) Init(config map[string]string) {
	p.clientId = config["client_id"]
	p.clientSecret = config["client_secret"]
	p.host = config["host"]
	p.entityId = config["entity_id"]
	p.application = config["application"]

	if val, ok := config["entity_type_id"]; ok {
		p.entityTypeId = val
	} else {
		p.entityTypeId = "MyEY-Users"
	}

	p.includeAssetAttributes = false
	if strings.EqualFold("TRUE", config["include_asset_attributes"]) {
		p.includeAssetAttributes = true
	}

	p.includeIdentity = false
	if strings.EqualFold("TRUE", config["include_identity"]) {
		p.includeIdentity = true
	}

	p.includeAccessPolicy = false
	if strings.EqualFold("TRUE", config["include_access_policy"]) {
		p.includeAccessPolicy = true
	}

	p.includeContext = false
	if strings.EqualFold("TRUE", config["include_context"]) {
		p.includeContext = true
	}
}

func (p *Plainid) buildRequestPayload() ([]byte, error) {
	rc := requestContextData{
		Application: []string{p.application},
	}

	r := request{
		EntityId:               p.entityId,
		EntityTypeId:           p.entityTypeId,
		ClientID:               p.clientId,
		ClientSecret:           p.clientSecret,
		IncludeAccessPolicy:    p.includeAccessPolicy,
		IncludeIdentity:        p.includeIdentity,
		IncludeAssetAttributes: p.includeAssetAttributes,
		IncludeContext:         p.includeContext,
		ContextData:            rc,
	}

	jsonRequest, err := json.Marshal(r)

	return jsonRequest, err
}

func (p *Plainid) CallPlainId() error {
	jsonRequest, err := p.buildRequestPayload()
	if err != nil {
		return err
	}

	httpRequest, err := http.NewRequest(http.MethodPost,
		p.host, bytes.NewBuffer(jsonRequest))
	if err != nil {
		return err
	}

	httpRequest.Header.Add("Content-Type", "application/json")
	httpResponse, err := http.DefaultClient.Do(httpRequest)

	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}

	p.StrResponse = string(body)
	log.Debug("msg", " Plain ID raw response: "+p.StrResponse)

	if err := json.Unmarshal(body, &p.vResponse); err != nil {
		log.Error("msg", " Failed unmarshaling PlainId response "+err.Error())
		return err
	}

	return nil
}

func GetPlainId() *Plainid {
	return &Plainid{}
}

func (p *Plainid) GetIDP(idpType string) string {
	log.Debug("msg", "Trying to find "+idpType+" in response"+
		fmt.Sprintf("%+v", p))

	for _, access := range p.vResponse.Response {
		for _, oaccess := range access.Access {
			for _, action := range oaccess.Actions {
				if strings.EqualFold(idpType, action.Action) {
					return oaccess.Path
				}
			}
		}
	}

	return ""
}

func (p *Plainid) IsUserAllowedToAccessApplication() bool {
	log.Debug("msg", fmt.Sprintf("Trying to find if user %s has access to the application %s",
		p.entityId, p.application))

	for _, access := range p.vResponse.Response {
		for _, oaccess := range access.Access {
			if strings.EqualFold(oaccess.ResourceType, "MyEY_application") &&
				strings.EqualFold(oaccess.Path, p.application) {
				log.Debug("msg", fmt.Sprintf("User %s has access to the application %s",
					p.entityId, p.application))
				return true
			}
		}
	}

	log.Debug("msg", fmt.Sprintf("User %s does not have access to the application %s",
		p.entityId, p.application))

	return false
}

func (p *Plainid) IsProjectionAccountAuthenticationRequired() string {
	log.Debug("msg", fmt.Sprintf("Does user %s nned projection account authentication for application %s",
		p.entityId, p.application))

	for _, access := range p.vResponse.Response {
		for _, oaccess := range access.Access {
			if strings.EqualFold(oaccess.ResourceType, "MyEY_projection_accounts") {
				log.Debug("msg", fmt.Sprintf(
					"User %s need projection account (%s) authentication for application %s",
					p.entityId, oaccess.Path, p.application))
				return oaccess.Path
			}
		}
	}

	log.Debug("msg", fmt.Sprintf(
		"User %s does not need projection account authentication for application %s",
		p.entityId, p.application))

	return ""
}

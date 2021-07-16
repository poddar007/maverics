package jwt

import (
	"fmt"
	"github.com/juju/errors"
	"time"
)

type Claims struct {
	claimsMap map[string]interface{}
}

func NewClaim() *Claims {
	claimsMap := make(map[string]interface{})
	claims := Claims{
		claimsMap: claimsMap,
	}

	return &claims
}

func (c *Claims) Set(key string, value interface{}) {
	c.claimsMap[key] = value
}

func (c *Claims) SetTime(key string, value time.Time) {
	c.Set(key, value.Unix())
}

func (c *Claims) SetAudience(value interface{}) {
	c.Set("aud", value)
}

func (c *Claims) SetSubject(value interface{}) {
	c.Set("sub", value)
}

func (c *Claims) SetIssuer(value interface{}) {
	c.Set("iss", value)
}

func (c *Claims) Get(key string) (interface{}, error) {
	result, ok := c.claimsMap[key]

	if !ok {
		return "", errors.New(fmt.Sprintf("Claim %s does not exist", key))
	}

	return result, nil
}

func (c *Claims) GetTime(key string) (time.Time, error) {
	result, err := c.Get(key)

	if err != nil {
		return time.Unix(0, 0), err
	}

	timeFloat, ok := result.(float64)

	if !ok {
		return time.Unix(0, 0), errors.New(fmt.Sprintf("Claim is not a valid fload %v", result))
	}

	return time.Unix(int64(timeFloat), 0), nil
}

func (c *Claims) HasClaim(key string) bool {
	_, ok := c.claimsMap[key]
	return ok
}

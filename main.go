package main

import (
	"Maverics/mfa"
	"os"
)

func main() {
	os.Setenv("CONFIG_FILE", "/Users/ap349/Documents/IdeaProjects/Maverics/config.json")
	provider := mfa.GetProvider(mfa.DUO)
	provider.Init(nil, nil)
	provider.SendAuthenticationRedirect(nil, nil, "ap349")

	/*
		t := jwt.New()
		t.Set("response_type", "code")
		t.Set("scope", "openid")
		t.Set("client_id", "TestClientId")
		t.Set(jwt.AudienceKey, "pingaud")

		buf, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			fmt.Printf("failed to generate JSON: %s\n", err)
			return
		}
		key := "h4Uvd84W6iZQMuwAqvnoDZL25d0Sle3YZLEm9GJp"
		signed,err := jwt.Sign(t, jwa.HS512, []byte(key))
		fmt.Printf("%s\n",string(signed))
		fmt.Printf("%T\n", buf)
	*/
}

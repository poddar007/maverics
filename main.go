package main

import (
	"mfa"
	"os"
)

func main() {
	var duo = &mfa.Duo{}
	os.Setenv("CONFIG_FILE", "/Users/ap349/Documents/IdeaProjects/Maverics/config.json")
	duo.Init()
	duo.IsDuoHealthy()
}

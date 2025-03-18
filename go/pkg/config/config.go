package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
)

var Cfg *Config

type Config struct{ KnownServicesFile string }

func Init(envPath string) {
	if envPath != "" {
		err := godotenv.Load(envPath)
		if err != nil {
			fmt.Printf("Could not load .env file: %s\n", err)
		}
	}

	Cfg = &Config{KnownServicesFile: os.Getenv("KNOWN_SERVICES_FILE")}
}

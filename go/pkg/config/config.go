package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
)

var Cfg *Config

type Config struct {
	KnownServicesFile string
	PrivateKeyFile    string
}

func Init(envPath string) {
	if envPath != "" {
		err := godotenv.Load(envPath)
		if err != nil {
			fmt.Printf("Could not load .env file: %s\n", err)
		}
	}

	Cfg = &Config{
		KnownServicesFile: getEnv("KNOWN_SERVICES_FILE", "known_services.txt"),
		PrivateKeyFile:    getEnv("PRIVATE_KEY_FILE", "private_key.pem")}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

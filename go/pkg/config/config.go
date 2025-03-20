package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

var Cfg *Config

type Config struct {
	KnownServicesFile string
	PrivateKeyFile    string
	MinPasswordLength int
	FileDir           string
	WorkingDir        string
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
		PrivateKeyFile:    getEnv("PRIVATE_KEY_FILE", "private_key.pem"),
		MinPasswordLength: getEnvInt("MIN_PASSWORD_LENGTH", 12),
		FileDir:           getEnv("FILE_DIR", "files"),
		WorkingDir:        getEnv("WORKING_DIRECTORY", "")}

	if Cfg.WorkingDir != "" {
		os.Chdir(Cfg.WorkingDir)
	} else {
		dir, _ := os.Getwd()
		Cfg.WorkingDir = dir
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if value, isInt := strconv.Atoi(value); isInt == nil {
			return value
		}
	}
	return fallback
}

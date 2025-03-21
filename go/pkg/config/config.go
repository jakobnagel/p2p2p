package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

var Cfg *Config

type Config struct {
	KnownKeysFile     string
	KnownHostsFile    string
	KnownFilesFile    string
	PrivateKeyFile    string
	MinPasswordLength int
	FileDir           string
	WorkingDir        string
}

func init() {
	if envMode, ok := os.LookupEnv("MODE"); ok {
		err := godotenv.Load(envMode + ".env")
		if err != nil {
			fmt.Printf("Could not load .env file: %s\n", err)
		}
	}

	Cfg = &Config{
		KnownKeysFile:     getEnv("KNOWN_KEYS_FILE", "known_keys.txt"),
		KnownHostsFile:    getEnv("KNOWN_HOSTS_FILE", "known_hosts.txt"),
		KnownFilesFile:    getEnv("KNOWN_FILES_FILE", "known_files.txt"),
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

	os.MkdirAll(Cfg.FileDir, 0755)
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

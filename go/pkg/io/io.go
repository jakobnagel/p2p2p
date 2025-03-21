package io

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"nagelbros.com/p2p2p/pkg/config"
)

const UndefinedPassword = "UNDEFINED"

func GetUserPassword() string {
	var password string = UndefinedPassword
	reader := bufio.NewReader(os.Stdin)

	for password == UndefinedPassword || len(password) < config.Cfg.MinPasswordLength {

		fmt.Print("Enter password: ")
		line, err := reader.ReadString('\n')

		if err != nil {
			fmt.Println(err)
		}

		password = strings.TrimSpace(line)
		if len(password) < config.Cfg.MinPasswordLength {
			fmt.Printf("Password must be at least %d characters long\n", config.Cfg.MinPasswordLength)
		}
	}

	return password
}

func GetConsent(prompt string) bool {
	var consent string
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%s [y/n]: ", prompt)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}

	consent = strings.TrimSpace(line)
	consent = strings.ToLower(consent)

	return consent == "y"
}

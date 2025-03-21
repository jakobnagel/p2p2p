package files

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"nagelbros.com/p2p2p/pkg/config"
	sec "nagelbros.com/p2p2p/pkg/security"
)

var knownFiles map[string]string = make(map[string]string)

// loads known files from file
func init() {
	file, err := os.Open(config.Cfg.KnownFilesFile)
	if os.IsNotExist(err) {
		os.Create(config.Cfg.KnownFilesFile)
		return
	}
	defer file.Close()

	r := bufio.NewReader(file)

	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil { // EOF
			break
		}

		fileName, hash, found := strings.Cut(line, " ")
		if !found {
			continue
		}

		knownFiles[fileName] = hash
	}
}

func RegisterFile(fileName, hash string) {
	if _, found := knownFiles[fileName]; found {
		return
	}

	knownFiles[fileName] = hash

	file, err := os.OpenFile(config.Cfg.KnownFilesFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("could not open known files file: %s", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("%s %s\n", fileName, hash))
	if err != nil {
		fmt.Printf("could not write to known files file: %s", err)
	}
}

func VerifyFile(fileData []byte, fileName string) bool {
	hash := sec.Hash.New()
	hash.Write(fileData)

	fileHash := fmt.Sprintf("%x", hash.Sum(nil))

	if knownHash, found := knownFiles[fileName]; found {
		return fileHash == knownHash
	} else {
		RegisterFile(fileName, fileHash)
		return true
	}
}

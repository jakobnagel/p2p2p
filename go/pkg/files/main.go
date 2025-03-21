package files

import (
	"fmt"
	"os"
	"path"
	"strings"

	"nagelbros.com/p2p2p/pkg/message"
	sec "nagelbros.com/p2p2p/pkg/security"
	pb "nagelbros.com/p2p2p/types/message"
)

func GetFiles(dir, password string) ([]*pb.FileMetadata, error) {
	dirObjs, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("could not read directory: %s", err)
	}

	var files []*pb.FileMetadata
	for _, dirObj := range dirObjs {
		if !dirObj.IsDir() {
			filePath := path.Join(dir, dirObj.Name())
			fileData, err := DecryptFromFile(filePath, password)
			if err != nil {
				return nil, fmt.Errorf("could not decrypt file: %s", err)
			}

			hash := sec.Hash.New()
			hash.Write(fileData)

			fileHash := hash.Sum(nil)
			fileName := strings.TrimSuffix(dirObj.Name(), ".enc") // remove .enc extension
			files = append(files, message.FileMetadata(fileName, fileHash))
		}
	}

	return files, nil
}

package io

import (
	"fmt"
	"os"
)

func GetFiles(dir string) ([]string, error) {
	dirObjs, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("could not read directory: %s", err)
	}

	var files []string
	for _, dirObj := range dirObjs {
		if !dirObj.IsDir() {
			files = append(files, dirObj.Name())
		}
	}

	return files, nil
}

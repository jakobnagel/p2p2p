package io

import (
	"testing"
)

func TestIO(t *testing.T) {
	password := GetUserPassword()
	t.Log(password)
}

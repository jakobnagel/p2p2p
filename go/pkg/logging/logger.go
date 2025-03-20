package logging

import (
	"io"
	"log"
)

type nullWriter struct{}

func (_ *nullWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

var w io.Writer = &nullWriter{}
var NullLogger = log.New(w, "", 0)

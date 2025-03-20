package test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"nagelbros.com/p2p2p/types/message"
)

func TestMarshal(t *testing.T) {
	msg := &message.Message{Type: message.MessageType_LIST_FILES}
	msgEncoded, err := proto.Marshal(msg)
	if err != nil {
		t.Errorf("Could not marshal message: %s", err)
	}

	t.Logf("Encoded message: %d", msgEncoded)

	msgDecoded := &message.Message{}
	err = proto.Unmarshal(msgEncoded, msgDecoded)
	if err != nil {
		t.Errorf("Could not unmarshal message: %s", err)
	}
}

func TestFileList(t *testing.T) {
	fileList := &message.FileList{
		Files: []*message.FileMetadata{
			{Name: "file1"},
			{Name: "file2"},
		},
	}

	msg := &message.Message{Type: message.MessageType_LIST_FILES, Payload: fileList}
	msgEncoded, err := proto.Marshal(msg)
	if err != nil {
		t.Errorf("Could not marshal message: %s", err)
	}

	t.Logf("Encoded message: %d", msgEncoded)

	msgDecoded := &message.Message{}
	err = proto.Unmarshal(msgEncoded, msgDecoded)
	if err != nil {
		t.Errorf("Could not unmarshal message: %s", err)
	}

	fileListDecoded := msgDecoded.GetFileList()
	for i, file := range fileListDecoded.Files {
		t.Logf("%d. %s", i+1, file.Name)
	}
}

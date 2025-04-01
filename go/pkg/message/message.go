package message

import (
	"nagelbros.com/p2p2p/types/message"
)

func ErrorMessage(reason string) *message.WrappedMessage {
	return &message.WrappedMessage{
		Payload: &message.WrappedMessage_Error{
			Error: &message.Error{Message: reason},
		},
	}
}

func FileData(fileName string, file []byte) *message.WrappedMessage {
	return &message.WrappedMessage{
		Payload: &message.WrappedMessage_FileDownload{
			FileDownload: &message.FileDownload{FileName: fileName, FileData: file},
		},
	}
}

func FileList(files []*message.FileMetadata) *message.WrappedMessage {
	fileList := &message.FileList{Files: files}
	return &message.WrappedMessage{
		Payload: &message.WrappedMessage_FileList{
			FileList: fileList,
		},
	}
}

func FileListRequest() *message.WrappedMessage {
	return &message.WrappedMessage{}
}

func FileMetadata(fileName string, hash []byte) *message.FileMetadata {
	return &message.FileMetadata{
		Name: fileName,
		Hash: hash,
	}
}

func FileDownloadRequest(fileName string) *message.WrappedMessage {
	return &message.WrappedMessage{
		Payload: &message.WrappedMessage_FileDownloadRequest{
			FileDownloadRequest: &message.FileDownloadRequest{FileName: fileName},
		},
	}
}

func FileUploadRequest(fileName string, file []byte) *message.WrappedMessage {
	return &message.WrappedMessage{
		Payload: &message.WrappedMessage_FileUploadRequest{
			FileUploadRequest: &message.FileUploadRequest{FileName: fileName, FileData: file},
		},
	}
}

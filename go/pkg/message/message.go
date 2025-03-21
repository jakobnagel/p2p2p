package message

import (
	"nagelbros.com/p2p2p/types/message"
)

func ErrorMessage(reason string) *message.Message {
	return &message.Message{
		Type: message.MessageType_ERROR,
		Payload: &message.Message_Error{
			Error: &message.Error{Message: reason},
		},
	}
}

func FileData(file []byte) *message.Message {
	return &message.Message{
		Type: message.MessageType_FILE,
		Payload: &message.Message_File{
			File: &message.File{Data: file},
		},
	}
}

func FileList(files []*message.FileMetadata) *message.Message {
	fileList := &message.FileList{Files: files}
	return &message.Message{
		Type: message.MessageType_FILE_LIST,
		Payload: &message.Message_FileList{
			FileList: fileList,
		},
	}
}

func FileListRequest() *message.Message {
	return &message.Message{
		Type: message.MessageType_FILE_LIST_REQUEST,
	}
}

func FileMetadata(fileName string, hash []byte) *message.FileMetadata {
	return &message.FileMetadata{
		Name: fileName,
		Hash: hash,
	}
}

func FileDownloadRequest(fileName string) *message.Message {
	return &message.Message{
		Type: message.MessageType_FILE_DOWNLOAD_REQUEST,
		Payload: &message.Message_FileDownloadRequest{
			FileDownloadRequest: &message.FileDownloadRequeset{FileName: fileName},
		},
	}
}

func FileUploadRequest(fileName string, file []byte) *message.Message {
	return &message.Message{
		Type: message.MessageType_FILE_UPLOAD_REQUEST,
		Payload: &message.Message_FileUploadRequest{
			FileUploadRequest: &message.FileUploadRequest{FileName: fileName, FileData: file},
		},
	}
}

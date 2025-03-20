// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v5.29.3
// source: pb/message.proto

package message

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// first thing sent by the client after secure connection is established
type MessageType int32

const (
	MessageType_FILE_DOWNLOAD_REQUEST MessageType = 0
	MessageType_FILE_UPLOAD_REQUEST   MessageType = 1
	MessageType_FILE_LIST_REQUEST     MessageType = 2
	MessageType_FILE                  MessageType = 3
	MessageType_FILE_LIST             MessageType = 4
	MessageType_DECLINE               MessageType = 5
	MessageType_CONFIRMATION          MessageType = 6
)

// Enum value maps for MessageType.
var (
	MessageType_name = map[int32]string{
		0: "FILE_DOWNLOAD_REQUEST",
		1: "FILE_UPLOAD_REQUEST",
		2: "FILE_LIST_REQUEST",
		3: "FILE",
		4: "FILE_LIST",
		5: "DECLINE",
		6: "CONFIRMATION",
	}
	MessageType_value = map[string]int32{
		"FILE_DOWNLOAD_REQUEST": 0,
		"FILE_UPLOAD_REQUEST":   1,
		"FILE_LIST_REQUEST":     2,
		"FILE":                  3,
		"FILE_LIST":             4,
		"DECLINE":               5,
		"CONFIRMATION":          6,
	}
)

func (x MessageType) Enum() *MessageType {
	p := new(MessageType)
	*p = x
	return p
}

func (x MessageType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MessageType) Descriptor() protoreflect.EnumDescriptor {
	return file_pb_message_proto_enumTypes[0].Descriptor()
}

func (MessageType) Type() protoreflect.EnumType {
	return &file_pb_message_proto_enumTypes[0]
}

func (x MessageType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MessageType.Descriptor instead.
func (MessageType) EnumDescriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{0}
}

// used to wrap encrypted messages
type MessageWrapper struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Message       []byte                 `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"` // encrypted
	Signature     []byte                 `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	Nonce         []byte                 `protobuf:"bytes,3,opt,name=nonce,proto3" json:"nonce,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MessageWrapper) Reset() {
	*x = MessageWrapper{}
	mi := &file_pb_message_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MessageWrapper) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageWrapper) ProtoMessage() {}

func (x *MessageWrapper) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageWrapper.ProtoReflect.Descriptor instead.
func (*MessageWrapper) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{0}
}

func (x *MessageWrapper) GetMessage() []byte {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *MessageWrapper) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *MessageWrapper) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

type Message struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	Type  MessageType            `protobuf:"varint,1,opt,name=type,proto3,enum=p2p2p.MessageType" json:"type,omitempty"`
	// Types that are valid to be assigned to Payload:
	//
	//	*Message_FileDownloadRequest
	//	*Message_FileList
	//	*Message_File
	Payload       isMessage_Payload `protobuf_oneof:"payload"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Message) Reset() {
	*x = Message{}
	mi := &file_pb_message_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{1}
}

func (x *Message) GetType() MessageType {
	if x != nil {
		return x.Type
	}
	return MessageType_FILE_DOWNLOAD_REQUEST
}

func (x *Message) GetPayload() isMessage_Payload {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *Message) GetFileDownloadRequest() *FileDownloadRequeset {
	if x != nil {
		if x, ok := x.Payload.(*Message_FileDownloadRequest); ok {
			return x.FileDownloadRequest
		}
	}
	return nil
}

func (x *Message) GetFileList() *FileList {
	if x != nil {
		if x, ok := x.Payload.(*Message_FileList); ok {
			return x.FileList
		}
	}
	return nil
}

func (x *Message) GetFile() *File {
	if x != nil {
		if x, ok := x.Payload.(*Message_File); ok {
			return x.File
		}
	}
	return nil
}

type isMessage_Payload interface {
	isMessage_Payload()
}

type Message_FileDownloadRequest struct {
	FileDownloadRequest *FileDownloadRequeset `protobuf:"bytes,2,opt,name=file_download_request,json=fileDownloadRequest,proto3,oneof"`
}

type Message_FileList struct {
	FileList *FileList `protobuf:"bytes,3,opt,name=file_list,json=fileList,proto3,oneof"`
}

type Message_File struct {
	File *File `protobuf:"bytes,4,opt,name=file,proto3,oneof"`
}

func (*Message_FileDownloadRequest) isMessage_Payload() {}

func (*Message_FileList) isMessage_Payload() {}

func (*Message_File) isMessage_Payload() {}

type Decline struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Reason        string                 `protobuf:"bytes,1,opt,name=reason,proto3" json:"reason,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Decline) Reset() {
	*x = Decline{}
	mi := &file_pb_message_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Decline) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Decline) ProtoMessage() {}

func (x *Decline) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Decline.ProtoReflect.Descriptor instead.
func (*Decline) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{2}
}

func (x *Decline) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

type Confirmation struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Message       string                 `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Confirmation) Reset() {
	*x = Confirmation{}
	mi := &file_pb_message_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Confirmation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Confirmation) ProtoMessage() {}

func (x *Confirmation) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Confirmation.ProtoReflect.Descriptor instead.
func (*Confirmation) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{3}
}

func (x *Confirmation) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

// Protocol messages
type FileDownloadRequeset struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	FileName      string                 `protobuf:"bytes,1,opt,name=file_name,json=fileName,proto3" json:"file_name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FileDownloadRequeset) Reset() {
	*x = FileDownloadRequeset{}
	mi := &file_pb_message_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FileDownloadRequeset) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FileDownloadRequeset) ProtoMessage() {}

func (x *FileDownloadRequeset) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FileDownloadRequeset.ProtoReflect.Descriptor instead.
func (*FileDownloadRequeset) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{4}
}

func (x *FileDownloadRequeset) GetFileName() string {
	if x != nil {
		return x.FileName
	}
	return ""
}

type FileUploadRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	FileName      string                 `protobuf:"bytes,1,opt,name=file_name,json=fileName,proto3" json:"file_name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FileUploadRequest) Reset() {
	*x = FileUploadRequest{}
	mi := &file_pb_message_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FileUploadRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FileUploadRequest) ProtoMessage() {}

func (x *FileUploadRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FileUploadRequest.ProtoReflect.Descriptor instead.
func (*FileUploadRequest) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{5}
}

func (x *FileUploadRequest) GetFileName() string {
	if x != nil {
		return x.FileName
	}
	return ""
}

type FileListRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FileListRequest) Reset() {
	*x = FileListRequest{}
	mi := &file_pb_message_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FileListRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FileListRequest) ProtoMessage() {}

func (x *FileListRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FileListRequest.ProtoReflect.Descriptor instead.
func (*FileListRequest) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{6}
}

type KeyMigrationRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *KeyMigrationRequest) Reset() {
	*x = KeyMigrationRequest{}
	mi := &file_pb_message_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *KeyMigrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyMigrationRequest) ProtoMessage() {}

func (x *KeyMigrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyMigrationRequest.ProtoReflect.Descriptor instead.
func (*KeyMigrationRequest) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{7}
}

type FileList struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Files         []*FileMetadata        `protobuf:"bytes,1,rep,name=files,proto3" json:"files,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FileList) Reset() {
	*x = FileList{}
	mi := &file_pb_message_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FileList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FileList) ProtoMessage() {}

func (x *FileList) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FileList.ProtoReflect.Descriptor instead.
func (*FileList) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{8}
}

func (x *FileList) GetFiles() []*FileMetadata {
	if x != nil {
		return x.Files
	}
	return nil
}

type FileMetadata struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FileMetadata) Reset() {
	*x = FileMetadata{}
	mi := &file_pb_message_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FileMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FileMetadata) ProtoMessage() {}

func (x *FileMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FileMetadata.ProtoReflect.Descriptor instead.
func (*FileMetadata) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{9}
}

func (x *FileMetadata) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type File struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Data          []byte                 `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *File) Reset() {
	*x = File{}
	mi := &file_pb_message_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *File) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*File) ProtoMessage() {}

func (x *File) ProtoReflect() protoreflect.Message {
	mi := &file_pb_message_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use File.ProtoReflect.Descriptor instead.
func (*File) Descriptor() ([]byte, []int) {
	return file_pb_message_proto_rawDescGZIP(), []int{10}
}

func (x *File) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *File) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_pb_message_proto protoreflect.FileDescriptor

var file_pb_message_proto_rawDesc = string([]byte{
	0x0a, 0x10, 0x70, 0x62, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x05, 0x70, 0x32, 0x70, 0x32, 0x70, 0x22, 0x5e, 0x0a, 0x0e, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x57, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x6d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x22, 0xe2, 0x01, 0x0a, 0x07, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x26, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x12, 0x2e, 0x70, 0x32, 0x70, 0x32, 0x70, 0x2e, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x51, 0x0a,
	0x15, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x70,
	0x32, 0x70, 0x32, 0x70, 0x2e, 0x46, 0x69, 0x6c, 0x65, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61,
	0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x65, 0x74, 0x48, 0x00, 0x52, 0x13, 0x66, 0x69, 0x6c,
	0x65, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x2e, 0x0a, 0x09, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x32, 0x70, 0x32, 0x70, 0x2e, 0x46, 0x69, 0x6c, 0x65,
	0x4c, 0x69, 0x73, 0x74, 0x48, 0x00, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x21, 0x0a, 0x04, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b,
	0x2e, 0x70, 0x32, 0x70, 0x32, 0x70, 0x2e, 0x46, 0x69, 0x6c, 0x65, 0x48, 0x00, 0x52, 0x04, 0x66,
	0x69, 0x6c, 0x65, 0x42, 0x09, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x21,
	0x0a, 0x07, 0x44, 0x65, 0x63, 0x6c, 0x69, 0x6e, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x22, 0x28, 0x0a, 0x0c, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x33, 0x0a, 0x14, 0x46,
	0x69, 0x6c, 0x65, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x65, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x4e, 0x61, 0x6d, 0x65,
	0x22, 0x30, 0x0a, 0x11, 0x46, 0x69, 0x6c, 0x65, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x4e, 0x61,
	0x6d, 0x65, 0x22, 0x11, 0x0a, 0x0f, 0x46, 0x69, 0x6c, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x15, 0x0a, 0x13, 0x4b, 0x65, 0x79, 0x4d, 0x69, 0x67, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x35, 0x0a, 0x08,
	0x46, 0x69, 0x6c, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x29, 0x0a, 0x05, 0x66, 0x69, 0x6c, 0x65,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x70, 0x32, 0x70, 0x32, 0x70, 0x2e,
	0x46, 0x69, 0x6c, 0x65, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x05, 0x66, 0x69,
	0x6c, 0x65, 0x73, 0x22, 0x22, 0x0a, 0x0c, 0x46, 0x69, 0x6c, 0x65, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x2e, 0x0a, 0x04, 0x46, 0x69, 0x6c, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x2a, 0x90, 0x01, 0x0a, 0x0b, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x15, 0x46, 0x49, 0x4c, 0x45, 0x5f,
	0x44, 0x4f, 0x57, 0x4e, 0x4c, 0x4f, 0x41, 0x44, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54,
	0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x55, 0x50, 0x4c, 0x4f, 0x41,
	0x44, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11, 0x46,
	0x49, 0x4c, 0x45, 0x5f, 0x4c, 0x49, 0x53, 0x54, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54,
	0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x46, 0x49, 0x4c, 0x45, 0x10, 0x03, 0x12, 0x0d, 0x0a, 0x09,
	0x46, 0x49, 0x4c, 0x45, 0x5f, 0x4c, 0x49, 0x53, 0x54, 0x10, 0x04, 0x12, 0x0b, 0x0a, 0x07, 0x44,
	0x45, 0x43, 0x4c, 0x49, 0x4e, 0x45, 0x10, 0x05, 0x12, 0x10, 0x0a, 0x0c, 0x43, 0x4f, 0x4e, 0x46,
	0x49, 0x52, 0x4d, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x06, 0x42, 0x1a, 0x5a, 0x18, 0x67, 0x6f,
	0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3b, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_pb_message_proto_rawDescOnce sync.Once
	file_pb_message_proto_rawDescData []byte
)

func file_pb_message_proto_rawDescGZIP() []byte {
	file_pb_message_proto_rawDescOnce.Do(func() {
		file_pb_message_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_pb_message_proto_rawDesc), len(file_pb_message_proto_rawDesc)))
	})
	return file_pb_message_proto_rawDescData
}

var file_pb_message_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_pb_message_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_pb_message_proto_goTypes = []any{
	(MessageType)(0),             // 0: p2p2p.MessageType
	(*MessageWrapper)(nil),       // 1: p2p2p.MessageWrapper
	(*Message)(nil),              // 2: p2p2p.Message
	(*Decline)(nil),              // 3: p2p2p.Decline
	(*Confirmation)(nil),         // 4: p2p2p.Confirmation
	(*FileDownloadRequeset)(nil), // 5: p2p2p.FileDownloadRequeset
	(*FileUploadRequest)(nil),    // 6: p2p2p.FileUploadRequest
	(*FileListRequest)(nil),      // 7: p2p2p.FileListRequest
	(*KeyMigrationRequest)(nil),  // 8: p2p2p.KeyMigrationRequest
	(*FileList)(nil),             // 9: p2p2p.FileList
	(*FileMetadata)(nil),         // 10: p2p2p.FileMetadata
	(*File)(nil),                 // 11: p2p2p.File
}
var file_pb_message_proto_depIdxs = []int32{
	0,  // 0: p2p2p.Message.type:type_name -> p2p2p.MessageType
	5,  // 1: p2p2p.Message.file_download_request:type_name -> p2p2p.FileDownloadRequeset
	9,  // 2: p2p2p.Message.file_list:type_name -> p2p2p.FileList
	11, // 3: p2p2p.Message.file:type_name -> p2p2p.File
	10, // 4: p2p2p.FileList.files:type_name -> p2p2p.FileMetadata
	5,  // [5:5] is the sub-list for method output_type
	5,  // [5:5] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_pb_message_proto_init() }
func file_pb_message_proto_init() {
	if File_pb_message_proto != nil {
		return
	}
	file_pb_message_proto_msgTypes[1].OneofWrappers = []any{
		(*Message_FileDownloadRequest)(nil),
		(*Message_FileList)(nil),
		(*Message_File)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_pb_message_proto_rawDesc), len(file_pb_message_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pb_message_proto_goTypes,
		DependencyIndexes: file_pb_message_proto_depIdxs,
		EnumInfos:         file_pb_message_proto_enumTypes,
		MessageInfos:      file_pb_message_proto_msgTypes,
	}.Build()
	File_pb_message_proto = out.File
	file_pb_message_proto_goTypes = nil
	file_pb_message_proto_depIdxs = nil
}

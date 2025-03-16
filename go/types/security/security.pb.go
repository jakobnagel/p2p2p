// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v5.29.3
// source: pb/security.proto

package security

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

// security
type RSAUpdateKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RsaPublicKey  *RsaPublicKey          `protobuf:"bytes,1,opt,name=RsaPublicKey,proto3" json:"RsaPublicKey,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RSAUpdateKey) Reset() {
	*x = RSAUpdateKey{}
	mi := &file_pb_security_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RSAUpdateKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RSAUpdateKey) ProtoMessage() {}

func (x *RSAUpdateKey) ProtoReflect() protoreflect.Message {
	mi := &file_pb_security_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RSAUpdateKey.ProtoReflect.Descriptor instead.
func (*RSAUpdateKey) Descriptor() ([]byte, []int) {
	return file_pb_security_proto_rawDescGZIP(), []int{0}
}

func (x *RSAUpdateKey) GetRsaPublicKey() *RsaPublicKey {
	if x != nil {
		return x.RsaPublicKey
	}
	return nil
}

// Base types
type RsaPublicKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	N             []byte                 `protobuf:"bytes,1,opt,name=n,proto3" json:"n,omitempty"`
	E             uint32                 `protobuf:"varint,2,opt,name=e,proto3" json:"e,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RsaPublicKey) Reset() {
	*x = RsaPublicKey{}
	mi := &file_pb_security_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RsaPublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RsaPublicKey) ProtoMessage() {}

func (x *RsaPublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_pb_security_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RsaPublicKey.ProtoReflect.Descriptor instead.
func (*RsaPublicKey) Descriptor() ([]byte, []int) {
	return file_pb_security_proto_rawDescGZIP(), []int{1}
}

func (x *RsaPublicKey) GetN() []byte {
	if x != nil {
		return x.N
	}
	return nil
}

func (x *RsaPublicKey) GetE() uint32 {
	if x != nil {
		return x.E
	}
	return 0
}

type DiffeHellman struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	DhPublicKey   []byte                 `protobuf:"bytes,1,opt,name=DhPublicKey,proto3" json:"DhPublicKey,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DiffeHellman) Reset() {
	*x = DiffeHellman{}
	mi := &file_pb_security_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DiffeHellman) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DiffeHellman) ProtoMessage() {}

func (x *DiffeHellman) ProtoReflect() protoreflect.Message {
	mi := &file_pb_security_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DiffeHellman.ProtoReflect.Descriptor instead.
func (*DiffeHellman) Descriptor() ([]byte, []int) {
	return file_pb_security_proto_rawDescGZIP(), []int{2}
}

func (x *DiffeHellman) GetDhPublicKey() []byte {
	if x != nil {
		return x.DhPublicKey
	}
	return nil
}

var File_pb_security_proto protoreflect.FileDescriptor

var file_pb_security_proto_rawDesc = string([]byte{
	0x0a, 0x11, 0x70, 0x62, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x32, 0x70, 0x32, 0x70, 0x22, 0x47, 0x0a, 0x0c, 0x52, 0x53,
	0x41, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x37, 0x0a, 0x0c, 0x52, 0x73,
	0x61, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x13, 0x2e, 0x70, 0x32, 0x70, 0x32, 0x70, 0x2e, 0x52, 0x73, 0x61, 0x50, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x0c, 0x52, 0x73, 0x61, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x22, 0x2a, 0x0a, 0x0c, 0x52, 0x73, 0x61, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x12, 0x0c, 0x0a, 0x01, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01,
	0x6e, 0x12, 0x0c, 0x0a, 0x01, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x01, 0x65, 0x22,
	0x30, 0x0a, 0x0c, 0x44, 0x69, 0x66, 0x66, 0x65, 0x48, 0x65, 0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x12,
	0x20, 0x0a, 0x0b, 0x44, 0x68, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x44, 0x68, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65,
	0x79, 0x42, 0x1c, 0x5a, 0x1a, 0x67, 0x6f, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x73, 0x65,
	0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x3b, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_pb_security_proto_rawDescOnce sync.Once
	file_pb_security_proto_rawDescData []byte
)

func file_pb_security_proto_rawDescGZIP() []byte {
	file_pb_security_proto_rawDescOnce.Do(func() {
		file_pb_security_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_pb_security_proto_rawDesc), len(file_pb_security_proto_rawDesc)))
	})
	return file_pb_security_proto_rawDescData
}

var file_pb_security_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_pb_security_proto_goTypes = []any{
	(*RSAUpdateKey)(nil), // 0: p2p2p.RSAUpdateKey
	(*RsaPublicKey)(nil), // 1: p2p2p.RsaPublicKey
	(*DiffeHellman)(nil), // 2: p2p2p.DiffeHellman
}
var file_pb_security_proto_depIdxs = []int32{
	1, // 0: p2p2p.RSAUpdateKey.RsaPublicKey:type_name -> p2p2p.RsaPublicKey
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_pb_security_proto_init() }
func file_pb_security_proto_init() {
	if File_pb_security_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_pb_security_proto_rawDesc), len(file_pb_security_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pb_security_proto_goTypes,
		DependencyIndexes: file_pb_security_proto_depIdxs,
		MessageInfos:      file_pb_security_proto_msgTypes,
	}.Build()
	File_pb_security_proto = out.File
	file_pb_security_proto_goTypes = nil
	file_pb_security_proto_depIdxs = nil
}

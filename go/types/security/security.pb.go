// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v5.29.3
// source: security.proto

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

type RsaPublicKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	N             []byte                 `protobuf:"bytes,1,opt,name=n,proto3" json:"n,omitempty"`
	E             uint32                 `protobuf:"varint,2,opt,name=e,proto3" json:"e,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RsaPublicKey) Reset() {
	*x = RsaPublicKey{}
	mi := &file_security_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RsaPublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RsaPublicKey) ProtoMessage() {}

func (x *RsaPublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_security_proto_msgTypes[0]
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
	return file_security_proto_rawDescGZIP(), []int{0}
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
	DhPublicKey   []byte                 `protobuf:"bytes,1,opt,name=dh_public_key,json=dhPublicKey,proto3" json:"dh_public_key,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DiffeHellman) Reset() {
	*x = DiffeHellman{}
	mi := &file_security_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DiffeHellman) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DiffeHellman) ProtoMessage() {}

func (x *DiffeHellman) ProtoReflect() protoreflect.Message {
	mi := &file_security_proto_msgTypes[1]
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
	return file_security_proto_rawDescGZIP(), []int{1}
}

func (x *DiffeHellman) GetDhPublicKey() []byte {
	if x != nil {
		return x.DhPublicKey
	}
	return nil
}

var File_security_proto protoreflect.FileDescriptor

var file_security_proto_rawDesc = string([]byte{
	0x0a, 0x0e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x05, 0x70, 0x32, 0x70, 0x32, 0x70, 0x22, 0x2a, 0x0a, 0x0c, 0x52, 0x73, 0x61, 0x50, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x0c, 0x0a, 0x01, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x01, 0x6e, 0x12, 0x0c, 0x0a, 0x01, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x01, 0x65, 0x22, 0x32, 0x0a, 0x0c, 0x44, 0x69, 0x66, 0x66, 0x65, 0x48, 0x65, 0x6c, 0x6c,
	0x6d, 0x61, 0x6e, 0x12, 0x22, 0x0a, 0x0d, 0x64, 0x68, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x64, 0x68, 0x50, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x42, 0x2d, 0x5a, 0x2b, 0x6e, 0x61, 0x67, 0x65, 0x6c,
	0x62, 0x72, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x32, 0x70, 0x32, 0x70, 0x2f, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x3b, 0x73, 0x65,
	0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_security_proto_rawDescOnce sync.Once
	file_security_proto_rawDescData []byte
)

func file_security_proto_rawDescGZIP() []byte {
	file_security_proto_rawDescOnce.Do(func() {
		file_security_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_security_proto_rawDesc), len(file_security_proto_rawDesc)))
	})
	return file_security_proto_rawDescData
}

var file_security_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_security_proto_goTypes = []any{
	(*RsaPublicKey)(nil), // 0: p2p2p.RsaPublicKey
	(*DiffeHellman)(nil), // 1: p2p2p.DiffeHellman
}
var file_security_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_security_proto_init() }
func file_security_proto_init() {
	if File_security_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_security_proto_rawDesc), len(file_security_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_security_proto_goTypes,
		DependencyIndexes: file_security_proto_depIdxs,
		MessageInfos:      file_security_proto_msgTypes,
	}.Build()
	File_security_proto = out.File
	file_security_proto_goTypes = nil
	file_security_proto_depIdxs = nil
}

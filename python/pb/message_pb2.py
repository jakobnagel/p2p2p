# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: message.proto
# Protobuf Python Version: 6.30.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    6,
    30,
    1,
    '',
    'message.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rmessage.proto\x12\x05p2p2p\"C\n\x0eMessageWrapper\x12\x0f\n\x07message\x18\x01 \x01(\x0c\x12\x11\n\tsignature\x18\x02 \x01(\x0c\x12\r\n\x05nonce\x18\x03 \x01(\x0c\"\xb7\x01\n\x07Message\x12 \n\x04type\x18\x01 \x01(\x0e\x32\x12.p2p2p.MessageType\x12<\n\x15\x66ile_download_request\x18\x02 \x01(\x0b\x32\x1b.p2p2p.FileDownloadRequesetH\x00\x12$\n\tfile_list\x18\x03 \x01(\x0b\x32\x0f.p2p2p.FileListH\x00\x12\x1b\n\x04\x66ile\x18\x04 \x01(\x0b\x32\x0b.p2p2p.FileH\x00\x42\t\n\x07payload\"\x19\n\x07\x44\x65\x63line\x12\x0e\n\x06reason\x18\x01 \x01(\t\"\x1f\n\x0c\x43onfirmation\x12\x0f\n\x07message\x18\x01 \x01(\t\")\n\x14\x46ileDownloadRequeset\x12\x11\n\tfile_name\x18\x01 \x01(\t\"&\n\x11\x46ileUploadRequest\x12\x11\n\tfile_name\x18\x01 \x01(\t\"\x11\n\x0f\x46ileListRequest\"\x15\n\x13KeyMigrationRequest\".\n\x08\x46ileList\x12\"\n\x05\x66iles\x18\x01 \x03(\x0b\x32\x13.p2p2p.FileMetadata\"\x1c\n\x0c\x46ileMetadata\x12\x0c\n\x04name\x18\x02 \x01(\t\"\"\n\x04\x46ile\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c*\x90\x01\n\x0bMessageType\x12\x19\n\x15\x46ILE_DOWNLOAD_REQUEST\x10\x00\x12\x17\n\x13\x46ILE_UPLOAD_REQUEST\x10\x01\x12\x15\n\x11\x46ILE_LIST_REQUEST\x10\x02\x12\x08\n\x04\x46ILE\x10\x03\x12\r\n\tFILE_LIST\x10\x04\x12\x0b\n\x07\x44\x45\x43LINE\x10\x05\x12\x10\n\x0c\x43ONFIRMATION\x10\x06\x42\x1aZ\x18go/types/message;messageb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'message_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'Z\030go/types/message;message'
  _globals['_MESSAGETYPE']._serialized_start=579
  _globals['_MESSAGETYPE']._serialized_end=723
  _globals['_MESSAGEWRAPPER']._serialized_start=24
  _globals['_MESSAGEWRAPPER']._serialized_end=91
  _globals['_MESSAGE']._serialized_start=94
  _globals['_MESSAGE']._serialized_end=277
  _globals['_DECLINE']._serialized_start=279
  _globals['_DECLINE']._serialized_end=304
  _globals['_CONFIRMATION']._serialized_start=306
  _globals['_CONFIRMATION']._serialized_end=337
  _globals['_FILEDOWNLOADREQUESET']._serialized_start=339
  _globals['_FILEDOWNLOADREQUESET']._serialized_end=380
  _globals['_FILEUPLOADREQUEST']._serialized_start=382
  _globals['_FILEUPLOADREQUEST']._serialized_end=420
  _globals['_FILELISTREQUEST']._serialized_start=422
  _globals['_FILELISTREQUEST']._serialized_end=439
  _globals['_KEYMIGRATIONREQUEST']._serialized_start=441
  _globals['_KEYMIGRATIONREQUEST']._serialized_end=462
  _globals['_FILELIST']._serialized_start=464
  _globals['_FILELIST']._serialized_end=510
  _globals['_FILEMETADATA']._serialized_start=512
  _globals['_FILEMETADATA']._serialized_end=540
  _globals['_FILE']._serialized_start=542
  _globals['_FILE']._serialized_end=576
# @@protoc_insertion_point(module_scope)

# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: protobuf/config.proto
# Protobuf Python Version: 5.28.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    28,
    3,
    '',
    'protobuf/config.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15protobuf/config.proto\x12\x08sliverpb\"\xed\x01\n\x0b\x44riveConfig\x12\x10\n\x08\x43lientID\x18\x01 \x01(\t\x12\x14\n\x0c\x43lientSecret\x18\x02 \x01(\t\x12\x14\n\x0cRefreshToken\x18\x03 \x01(\t\x12\x11\n\tUserAgent\x18\x04 \x01(\t\x12\x16\n\x0eStartExtension\x18\x05 \x01(\t\x12\x15\n\rSendExtension\x18\x06 \x01(\t\x12\x15\n\rRecvExtension\x18\x07 \x01(\t\x12\x19\n\x11RegisterExtension\x18\x08 \x01(\t\x12\x16\n\x0e\x43loseExtension\x18\t \x01(\t\x12\x14\n\x0cPollInterval\x18\n \x01(\r\"\x89\x02\n\nHttpConfig\x12\x11\n\tPollPaths\x18\x01 \x03(\t\x12\x11\n\tPollFiles\x18\x02 \x03(\t\x12\x14\n\x0cSessionPaths\x18\x03 \x03(\t\x12\x14\n\x0cSessionFiles\x18\x04 \x03(\t\x12\x12\n\nClosePaths\x18\x05 \x03(\t\x12\x12\n\nCloseFiles\x18\x06 \x03(\t\x12\x11\n\tUserAgent\x18\x07 \x01(\t\x12\x11\n\tOtpSecret\x18\x08 \x01(\t\x12\x1b\n\x13MinNumberOfSegments\x18\t \x01(\r\x12\x1b\n\x13MaxNumberOfSegments\x18\n \x01(\r\x12\x14\n\x0cPollInterval\x18\x0b \x01(\r\x12\x0b\n\x03URL\x18\x0c \x01(\t\"\"\n\x0bPivotConfig\x12\x13\n\x0b\x42indAddress\x18\x01 \x01(\t\"\xbc\x04\n\x06\x43onfig\x12\x17\n\x0fServerPublicKey\x18\x01 \x01(\t\x12\x15\n\rPeerPublicKey\x18\x02 \x01(\t\x12\x16\n\x0ePeerPrivateKey\x18\x03 \x01(\t\x12\x1f\n\x17ServerMinisignPublicKey\x18\x04 \x01(\t\x12\x12\n\nSliverName\x18\x05 \x01(\t\x12\x10\n\x08\x43onfigID\x18\x06 \x01(\t\x12!\n\x19PeerAgePublicKeySignature\x18\x07 \x01(\t\x12\x14\n\x0c\x45ncoderNonce\x18\x08 \x01(\x04\x12\x1b\n\x13MaxConnectionErrors\x18\t \x01(\r\x12\x19\n\x11ReconnectInterval\x18\n \x01(\x04\x12(\n\x08Protocol\x18\x0b \x01(\x0e\x32\x16.sliverpb.ProtocolType\x12#\n\x04Type\x18\x0c \x01(\x0e\x32\x15.sliverpb.ImplantType\x12+\n\x0c\x44riveConfigs\x18\r \x03(\x0b\x32\x15.sliverpb.DriveConfig\x12)\n\x0bHttpConfigs\x18\x0e \x03(\x0b\x32\x14.sliverpb.HttpConfig\x12+\n\x0cPivotConfigs\x18\x0f \x03(\x0b\x32\x15.sliverpb.PivotConfig\x12\x0c\n\x04Loot\x18\x10 \x01(\x08\x12\x15\n\rLootClipboard\x18\x11 \x01(\x08\x12\r\n\x05Proxy\x18\x12 \x01(\t\x12\x12\n\nSliverPath\x18\x13 \x01(\t\x12\x16\n\x0eMainExecutable\x18\x14 \x01(\t*D\n\x0cProtocolType\x12\x08\n\x04HTTP\x10\x00\x12\t\n\x05\x44rive\x10\x01\x12\x07\n\x03TCP\x10\x02\x12\x07\n\x03UDP\x10\x03\x12\r\n\tNamedPipe\x10\x04*1\n\x0bImplantType\x12\x0b\n\x07Session\x10\x00\x12\n\n\x06\x42\x65\x61\x63on\x10\x01\x12\t\n\x05Pivot\x10\x02\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'protobuf.config_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_PROTOCOLTYPE']._serialized_start=1154
  _globals['_PROTOCOLTYPE']._serialized_end=1222
  _globals['_IMPLANTTYPE']._serialized_start=1224
  _globals['_IMPLANTTYPE']._serialized_end=1273
  _globals['_DRIVECONFIG']._serialized_start=36
  _globals['_DRIVECONFIG']._serialized_end=273
  _globals['_HTTPCONFIG']._serialized_start=276
  _globals['_HTTPCONFIG']._serialized_end=541
  _globals['_PIVOTCONFIG']._serialized_start=543
  _globals['_PIVOTCONFIG']._serialized_end=577
  _globals['_CONFIG']._serialized_start=580
  _globals['_CONFIG']._serialized_end=1152
# @@protoc_insertion_point(module_scope)

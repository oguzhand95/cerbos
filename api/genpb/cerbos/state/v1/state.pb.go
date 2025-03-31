// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: cerbos/state/v1/state.proto

package statev1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
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

type TelemetryState struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Uuid          string                 `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	LastTimestamp *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=last_timestamp,json=lastTimestamp,proto3" json:"last_timestamp,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TelemetryState) Reset() {
	*x = TelemetryState{}
	mi := &file_cerbos_state_v1_state_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TelemetryState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TelemetryState) ProtoMessage() {}

func (x *TelemetryState) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_state_v1_state_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TelemetryState.ProtoReflect.Descriptor instead.
func (*TelemetryState) Descriptor() ([]byte, []int) {
	return file_cerbos_state_v1_state_proto_rawDescGZIP(), []int{0}
}

func (x *TelemetryState) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *TelemetryState) GetLastTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.LastTimestamp
	}
	return nil
}

var File_cerbos_state_v1_state_proto protoreflect.FileDescriptor

const file_cerbos_state_v1_state_proto_rawDesc = "" +
	"\n" +
	"\x1bcerbos/state/v1/state.proto\x12\x0fcerbos.state.v1\x1a\x1fgoogle/protobuf/timestamp.proto\"g\n" +
	"\x0eTelemetryState\x12\x12\n" +
	"\x04uuid\x18\x01 \x01(\tR\x04uuid\x12A\n" +
	"\x0elast_timestamp\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\rlastTimestampB<Z:github.com/cerbos/cerbos/api/genpb/cerbos/state/v1;statev1b\x06proto3"

var (
	file_cerbos_state_v1_state_proto_rawDescOnce sync.Once
	file_cerbos_state_v1_state_proto_rawDescData []byte
)

func file_cerbos_state_v1_state_proto_rawDescGZIP() []byte {
	file_cerbos_state_v1_state_proto_rawDescOnce.Do(func() {
		file_cerbos_state_v1_state_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_cerbos_state_v1_state_proto_rawDesc), len(file_cerbos_state_v1_state_proto_rawDesc)))
	})
	return file_cerbos_state_v1_state_proto_rawDescData
}

var file_cerbos_state_v1_state_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_cerbos_state_v1_state_proto_goTypes = []any{
	(*TelemetryState)(nil),        // 0: cerbos.state.v1.TelemetryState
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_cerbos_state_v1_state_proto_depIdxs = []int32{
	1, // 0: cerbos.state.v1.TelemetryState.last_timestamp:type_name -> google.protobuf.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_cerbos_state_v1_state_proto_init() }
func file_cerbos_state_v1_state_proto_init() {
	if File_cerbos_state_v1_state_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_cerbos_state_v1_state_proto_rawDesc), len(file_cerbos_state_v1_state_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cerbos_state_v1_state_proto_goTypes,
		DependencyIndexes: file_cerbos_state_v1_state_proto_depIdxs,
		MessageInfos:      file_cerbos_state_v1_state_proto_msgTypes,
	}.Build()
	File_cerbos_state_v1_state_proto = out.File
	file_cerbos_state_v1_state_proto_goTypes = nil
	file_cerbos_state_v1_state_proto_depIdxs = nil
}

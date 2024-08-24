#pragma once

typedef enum _WireType {
	Varint = 0,
	Fixed64,
	LengthDelimited,
	StartGroup,
	EndGroup,
	Fixed32,
	Repeated,
	StructType
} WireType;

typedef struct _PBElement {
	WireType Type;
	DWORD dwFieldIdx;
	PBYTE pMarshalledData;
	DWORD cbMarshalledData;
	DWORD dwNumberOfSubElement;
	struct _PBElement** SubElements;
} PBElement, *PPBElement;

PBYTE MarshalVarInt
(
	_In_ UINT64 uValue,
	_Out_ PDWORD pcbOutput
);

PPBElement CreateBytesElement
(
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ DWORD dwFieldIdx
);

PPBElement CreateVarIntElement
(
	_In_ UINT64 uValue,
	_In_ DWORD dwFieldIdx
);

PPBElement CreateRepeatedVarIntElement
(
	_In_ PUINT64 pIntList,
	_In_ DWORD dwCount,
	_In_ DWORD dwFieldIdx
);

PPBElement CreateRepeatedBytesElement
(
	_In_ PBYTE* pArrayOfBytes,
	_In_ PDWORD pArrayOfSize,
	_In_ DWORD dwCount,
	_In_ DWORD dwFieldIdx
);
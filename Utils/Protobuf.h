#pragma once

typedef enum _WireType {
	Varint = 0,
	RepeatedVarint,
	Bytes,
	RepeatedBytes,
	StructType,
	RepeatedStruct
} WireType;

typedef struct _BUFFER {
	PBYTE pBuffer;
	DWORD cbBuffer;
} BUFFER, *PBUFFER;

typedef struct _PBElement {
	WireType Type;
	PBYTE pMarshalledData;
	DWORD cbMarshalledData;
	DWORD dwFieldIdx;
	DWORD dwNumberOfSubElement;
	struct _PBElement** SubElements;
} PBElement, *PPBElement;

VOID FreeBuffer
(
	_In_ PBUFFER pBuffer
);

PBYTE MarshalVarInt
(
	_In_ UINT64 uValue,
	_Out_ PDWORD pcbOutput
);

UINT64 UnmarshalVarInt
(
	_In_ PBYTE pInput,
	_Out_opt_ PDWORD pNumberOfBytesRead
);

PBUFFER UnmarshalBytes
(
	_In_ PBYTE pInput,
	_Out_ PDWORD pNumberOfBytesRead
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
	_In_ DWORD dwNumberOfEntries,
	_In_ DWORD dwFieldIdx
);

PPBElement CreateRepeatedBytesElement
(
	_In_ PBYTE* pArrayOfBytes,
	_In_ PDWORD pArrayOfSize,
	_In_ DWORD dwNumberOfEntries,
	_In_ DWORD dwFieldIdx
);

PPBElement CreateStructElement
(
	_In_ PPBElement* pElementList,
	_In_ DWORD dwCount,
	_In_ DWORD dwFieldIdx
);

PPBElement CreateRepeatedStructElement
(
	_In_ PPBElement* pElementList,
	_In_ DWORD cElementList,
	_In_ DWORD dwFieldIdx
);

VOID FreeElement
(
	_In_ PPBElement pElement
);

PBYTE* UnmarshalRepeatedBytes
(
	_In_ PPBElement pElement,
	_In_ PBYTE pInput,
	_Out_ PDWORD pdwNumberOfBytesRead
);

PUINT64 UnmarshalRepeatedVarInt
(
	_In_ PBYTE pInput,
	_Out_ PDWORD pdwNumberOfBytesRead
);

LPVOID* UnmarshalStruct
(
	_In_ PPBElement* pElementList,
	_In_ DWORD dwNumberOfEntries,
	_In_ PBYTE pInput,
	_In_ DWORD cbInput,
	_Out_opt_ PDWORD pNumberOfBytesRead
);
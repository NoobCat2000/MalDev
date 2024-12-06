#pragma once

#define FORMAT_GUID { 0x23170F69, 0x40C1, 0x278A, { 0x10, 0x00, 0x00, 0x01, 0x10, 0, 0x00, 0x00 } }
#define ZIP_GUID 0x01;
#define BZIP2_GUID 0x02;
#define RAR_GUID 0x03;
#define ARJ_GUID 0x04;
#define Z_GUID 0x05;
#define LZH_GUID 0x06;
#define SEVENZIP_GUID 0x07;
#define CAB_GUID 0x08;
#define NSIS_GUID 0x09;
#define LZMA_GUID 0x0A;
#define LZMA86_GUID 0x0B;
#define XZ_GUID 0x0C;
#define PPMD_GUID 0x0D;
#define VHDX_GUID 0xC4;
#define COFF_GUID 0xC6;
#define EXT_GUID 0xC7;
#define VMDK_GUID 0xC8;
#define VDI_GUID 0xC9;
#define QCOW_GUID 0xCA;
#define GPT_GUID 0xCB;
#define RAR5_GUID 0xCC;
#define IHEX_GUID 0xCD;
#define HXS_GUID 0xCE;
#define TE_GUID 0xCF;
#define UEFIC_GUID 0xD0;
#define UEFIS_GUID 0xD1;
#define SQUASHFS_GUID 0xD2;
#define CRAMFS_GUID 0xD3;
#define APM_GUID 0xD4;
#define MSLZ_GUID 0xD5;
#define FLV_GUID 0xD6;
#define SWF_GUID 0xD7;
#define SWFC_GUID 0xD8;
#define NTFS_GUID 0xD9;
#define FAT_GUID 0xDA;
#define MBR_GUID 0xDB;
#define VHD_GUID 0xDC;
#define PE_GUID 0xDD;
#define ELF_GUID 0xDE;
#define MACHO_GUID 0xDF;
#define UDF_GUID 0xE0;
#define XAR_GUID 0xE1;
#define MUB_GUID 0xE2;
#define HFS_GUID 0xE3;
#define DMG_GUID 0xE4;
#define COMPOUND_GUID 0xE5;
#define WIM_GUID 0xE6;
#define ISO_GUID 0xE7;
#define CHM_GUID 0xE9;
#define SPLIT_GUID 0xEA;
#define RPM_GUID 0xEB;
#define DEB_GUID 0xEC;
#define CPIO_GUID 0xED;
#define TAR_GUID 0xEE;
#define GZIP_GUID 0xEF;

typedef struct _IInStream IInStream;
typedef struct _ISequentialOutStream ISequentialOutStream;
typedef struct _IProgress IProgress;
typedef struct _IArchiveExtractCallback IArchiveExtractCallback;
typedef struct _IArchiveOpenCallback IArchiveOpenCallback;
typedef struct _IInArchive IInArchive;

typedef enum _CompressFormat {
    Rar,
    Rar5,
    SevenZip,
    BZip2,
    GZip,
    Wim,
    Xz,
    Zip,
    APM,
    Arj,
    Cab,
    Chm,
    Compound,
    Cpio,
    Deb,
    Elf,
    Pe,
    Flv,
    Lzma,
    Lzma86,
    Macho,
    Mub,
    Mslz,
    Ppmd,
    QCow,
    Rpm,
    SquashFS,
    Swf,
    Swfc,
    TE,
    VMDK,
    VDI,
    Vhd,
    Xar,
    Z
} CompressFormat;

struct ISequentialOutStreamVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
        __RPC__in ISequentialOutStream* This,
        __RPC__in REFIID riid,
        _COM_Outptr_ LPVOID* ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in ISequentialOutStream* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in ISequentialOutStream* This);

    HRESULT(STDMETHODCALLTYPE* Write)(
        __RPC__in IProgress* This,
        void* data,
        UINT32 size,
        PUINT32 processedSize);
};

struct _ISequentialOutStream {
    struct ISequentialOutStreamVtbl* vtbl;
};

struct IProgressVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
        __RPC__in IProgress* This,
        __RPC__in REFIID riid,
        _COM_Outptr_ LPVOID* ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in IProgress* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in IProgress* This);

    HRESULT(STDMETHODCALLTYPE* SetTotal)(
        __RPC__in IProgress* This,
        UINT64 total);

    HRESULT(STDMETHODCALLTYPE* SetCompleted)(
        __RPC__in IProgress* This,
        PUINT64 completeValue);
};

struct _IProgress {
    struct IProgressVtbl* vtbl;
};

struct IArchiveExtractCallbackVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
        __RPC__in IArchiveExtractCallback* This,
        __RPC__in REFIID riid,
        _COM_Outptr_ LPVOID* ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in IArchiveExtractCallback* This);


    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in IArchiveExtractCallback* This);

    HRESULT(STDMETHODCALLTYPE* SetTotal)(
        __RPC__in IArchiveExtractCallback* This,
        UINT64 total);

    HRESULT(STDMETHODCALLTYPE* SetCompleted)(
        __RPC__in IArchiveExtractCallback* This,
        PUINT64 completeValue);

    HRESULT(STDMETHODCALLTYPE* GetStream)(
        __RPC__in IArchiveExtractCallback* This,
        UINT32 index,
        ISequentialOutStream** outStream,
        INT32 askExtractMode);

    HRESULT(STDMETHODCALLTYPE* PrepareOperation)(
        __RPC__in IArchiveExtractCallback* This,
        INT32 askExtractMode);

    HRESULT(STDMETHODCALLTYPE* SetOperationResult)(
        __RPC__in IArchiveExtractCallback* This,
        INT32 opRes);
};

struct _IArchiveExtractCallback {
    struct IArchiveExtractCallbackVtbl* vtbl;
};

struct IInStreamVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
        __RPC__in IInStream* This,
        __RPC__in REFIID riid,
        _COM_Outptr_ LPVOID* ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in IInStream* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in IInStream* This);

    HRESULT(STDMETHODCALLTYPE* Read)(
        __RPC__in IInStream* This,
        LPVOID data,
        UINT32 size,
        PUINT32 processedSize);

    HRESULT(STDMETHODCALLTYPE* Seek)(
        __RPC__in IInStream* This,
        INT64 offset,
        UINT32 seekOrigin,
        PUINT64 newPosition);
};

struct _IInStream {
    struct IInStreamVtbl* vtbl;
    LONG m_lRef;
    PBUFFER pBuffer;
    DWORD dwPos;
};

struct IArchiveOpenCallbackVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
        __RPC__in IArchiveOpenCallback* This,
        __RPC__in REFIID riid,
        _COM_Outptr_ LPVOID* ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in IArchiveOpenCallback* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in IArchiveOpenCallback* This);

    HRESULT(STDMETHODCALLTYPE* SetTotal)(
        __RPC__in IArchiveOpenCallback* This,
        PUINT64 files,
        PUINT64 bytes);

    HRESULT(STDMETHODCALLTYPE* SetCompleted)(
        __RPC__in IArchiveOpenCallback* This,
        PUINT64 files,
        PUINT64 bytes);
};

struct _IArchiveOpenCallback {
    struct IArchiveOpenCallbackVtbl* vtbl;
};

struct IInArchiveVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            __RPC__in IInArchive* This,
            __RPC__in REFIID riid,
            _COM_Outptr_  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            __RPC__in IInArchive* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            __RPC__in IInArchive* This);

    HRESULT(STDMETHODCALLTYPE* Open)(
        __RPC__in IInArchive* This,
        IInStream* stream,
        PUINT64 maxCheckStartPosition,
        IArchiveOpenCallback* openCallback);

    HRESULT(STDMETHODCALLTYPE* Close)(
        __RPC__in IInArchive* This);

    HRESULT(STDMETHODCALLTYPE* GetNumberOfItems)(
        __RPC__in IInArchive* This,
        PUINT32 numItems);

    HRESULT(STDMETHODCALLTYPE* GetProperty)(
        __RPC__in IInArchive* This,
        UINT32 index, PROPID propID, PROPVARIANT *value);

    HRESULT(STDMETHODCALLTYPE* Extract)(
        __RPC__in IInArchive* This,
        PUINT32 indices,
        UINT32 numItems,
        INT32 testMode,
        IArchiveExtractCallback *extractCallback);

    HRESULT(STDMETHODCALLTYPE* GetArchiveProperty)(
        __RPC__in IInArchive* This,
        PROPID propID,
        PROPVARIANT *value);

    HRESULT(STDMETHODCALLTYPE* GetNumberOfProperties)(
        __RPC__in IInArchive* This,
        PUINT32 numProps);

    HRESULT(STDMETHODCALLTYPE* GetPropertyInfo)(
        __RPC__in IInArchive* This,
        UINT32 index,
        BSTR *name,
        PROPID *propID,
        VARTYPE *varType);

    HRESULT(STDMETHODCALLTYPE* GetNumberOfArchiveProperties)(
        __RPC__in IInArchive* This,
        PUINT32 numProps);

    HRESULT(STDMETHODCALLTYPE* GetArchivePropertyInfo)(
        __RPC__in IInArchive* This,
        UINT32 index,
        BSTR *name,
        PROPID *propID,
        VARTYPE *varType);
};

UINT32 IInStream_AddRef
(
    IInStream* This
);

HRESULT IInStream_QueryInterface
(
    _In_ IInStream* This,
    _In_ REFIID riid,
    _Out_ void** ppv
);

UINT32 IInStream_Release
(
    _In_ IInStream* This
);

HRESULT IInStream_Read
(
    _In_ IInStream* This,
    _In_ PBYTE pData,
    _In_ DWORD dwSize,
    _Out_ PDWORD pProcessedSize
);

HRESULT IInStream_Seek
(
    _In_ IInStream* This,
    _In_ INT64 Offset,
    _In_ UINT32 uSeekOrigin,
    _In_ PUINT64 pNewPosition
);

struct _IInArchive {
    struct IInArchiveVtbl* vtbl;
};

PGUID FindFormatBySignature
(
    _In_ UINT64 uSignature
);
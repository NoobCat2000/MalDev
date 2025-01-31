#include "pch.h"

//PGUID FindFormatBySignature
//(
//	_In_ UINT64 uSignature
//)
//{
//    PGUID pResult = NULL;
//
//    UINT64 uRarSignature = 0x526172211A070000; // Rar! 0x1A 0x07 0x00
//    UINT64 uRar5Signature = 0x526172211A070100; // Rar! 0x1A 0x07 0x01 0x00
//    UINT64 uSevenzipSignature = 0x377ABCAF271C0000; // 7z 0xBC 0xAF 0x27 0x1C
//    UINT64 uBzip2Signature = 0x425A680000000000; // BZh
//    UINT64 uGzipSignature = 0x1F8B080000000000; // 0x1F 0x8B 0x08
//    UINT64 uWimSignature = 0x4D5357494D000000; // MSWIM 0x00 0x00 0x00
//    UINT64 uXzSignature = 0xFD377A585A000000; // 0xFD 7zXZ 0x00
//    UINT64 uZipSignature = 0x504B000000000000; // PK
//    UINT64 uApmSignature = 0x4552000000000000; // ER
//    UINT64 uArjSignature = 0x60EA000000000000; // `EA
//    UINT64 uCabSignature = 0x4D53434600000000; // MSCF 0x00 0x00 0x00 0x00
//    UINT64 uChmSignature = 0x4954534603000000; // ITSF 0x03
//    UINT64 uCompoundSignature = 0xD0CF11E0A1B11AE1; // 0xD0 0xCF 0x11 0xE0 0xA1 0xB1 0x1A 0xE1
//    UINT64 uCpioSignature1 = 0xC771000000000000; // 0xC7 q
//    UINT64 uCpioSignature2 = 0x71C7000000000000; // q 0xC7
//    UINT64 uCpioSignature3 = 0x3037303730000000; // 07070
//    UINT64 uDebSignature = 0x213C617263683E00; // !<arch>0A
//    UINT64 uElfSignature = 0x7F454C4600000000; // 0x7F ELF
//    UINT64 uPeSignature = 0x4D5A000000000000; // MZ
//    UINT64 uFlvSignature = 0x464C560100000000; // FLV 0x01
//    UINT64 uLzmaSignature = 0x5D00000000000000; //
//    UINT64 uLzma86Signature = 0x015D000000000000; //
//    UINT64 uMachoSignature1 = 0xCEFAEDFE00000000; // 0xCE 0xFA 0xED 0xFE
//    UINT64 uMachoSignature2 = 0xCFFAEDFE00000000; // 0xCF 0xFA 0xED 0xFE
//    UINT64 uMachoSignature3 = 0xFEEDFACE00000000; // 0xFE 0xED 0xFA 0xCE
//    UINT64 uMachoSignature4 = 0xFEEDFACF00000000; // 0xFE 0xED 0xFA 0xCF
//    UINT64 uMubSignature1 = 0xCAFEBABE00000000; // 0xCA 0xFE 0xBA 0xBE 0x00 0x00 0x00
//    UINT64 uMubSignature2 = 0xB9FAF10E00000000; // 0xB9 0xFA 0xF1 0x0E
//    UINT64 uMslzSignature = 0x535A444488F02733; // SZDD 0x88 0xF0 '3
//    UINT64 uPpmdSignature = 0x8FAFAC8400000000; // 0x8F 0xAF 0xAC 0x84
//    UINT64 uQcowSignature = 0x514649FB00000000; // QFI 0xFB 0x00 0x00 0x00
//    UINT64 uRpmSignature = 0xEDABEEDB00000000; // 0xED 0xAB 0xEE 0xDB
//    UINT64 uSquashfsSignature1 = 0x7371736800000000; // sqsh
//    UINT64 uSquashfsSignature2 = 0x6873717300000000; // hsqs
//    UINT64 uSquashfsSignature3 = 0x7368737100000000; // shsq
//    UINT64 uSquashfsSignature4 = 0x7173687300000000; // qshs
//    UINT64 uSwfSignature = 0x4657530000000000; // FWS
//    UINT64 uSwfcSignature1 = 0x4357530000000000; // CWS
//    UINT64 uSwfcSignature2 = 0x5A57530000000000; // ZWS
//    UINT64 uTeSignature = 0x565A000000000000; // VZ
//    UINT64 uVmdkSignature = 0x4B444D0000000000; // KDMV
//    UINT64 uVdiSignature = 0x3C3C3C2000000000; // Alternatively, 0x7F10DABE at offset 0x40
//    UINT64 uVhdSignature = 0x636F6E6563746978; // conectix
//    UINT64 uXarSignature = 0x78617221001C0000; // xar! 0x00 0x1C
//    UINT64 uZSignature1 = 0x1F9D000000000000; // 0x1F 0x9D
//    UINT64 uZSignature2 = 0x1FA0000000000000; // 0x1F 0xA0
//    GUID Temp = FORMAT_GUID;
//    pResult = ALLOC(sizeof(GUID));
//    DWORD i = 0;
//    UINT64 uBaseSignatureMask = 0xFFFFFFFFFFFFFFFFULL;
//
//    for (i = 0; i < sizeof(UINT64); i++) {
//        if (uSignature == uRarSignature) {
//            Temp.Data4[5] = RAR_GUID;
//        }
//        else if (uSignature == uRar5Signature) {
//            Temp.Data4[5] = RAR5_GUID;
//        }
//        else if (uSignature == uSevenzipSignature) {
//            Temp.Data4[5] = SEVENZIP_GUID;
//        }
//        else if (uSignature == uBzip2Signature) {
//            Temp.Data4[5] = BZIP2_GUID;
//        }
//        else if (uSignature == uGzipSignature) {
//            Temp.Data4[5] = GZIP_GUID;
//        }
//        else if (uSignature == uWimSignature) {
//            Temp.Data4[5] = WIM_GUID;
//        }
//        else if (uSignature == uXzSignature) {
//            Temp.Data4[5] = XZ_GUID;
//        }
//        else if (uSignature == uZipSignature) {
//            Temp.Data4[5] = ZIP_GUID;
//        }
//        else if (uSignature == uApmSignature) {
//            Temp.Data4[5] = APM_GUID;
//        }
//        else if (uSignature == uArjSignature) {
//            Temp.Data4[5] = ARJ_GUID;
//        }
//        else if (uSignature == uCabSignature) {
//            Temp.Data4[5] = CAB_GUID;
//        }
//        else if (uSignature == uChmSignature) {
//            Temp.Data4[5] = CHM_GUID;
//        }
//        else if (uSignature == uCompoundSignature) {
//            Temp.Data4[5] = COMPOUND_GUID;
//        }
//        else if (uSignature == uCpioSignature1) {
//            Temp.Data4[5] = CPIO_GUID;
//        }
//        else if (uSignature == uCpioSignature2) {
//            Temp.Data4[5] = CPIO_GUID;
//        }
//        else if (uSignature == uCpioSignature3) {
//            Temp.Data4[5] = CPIO_GUID;
//        }
//        else if (uSignature == uDebSignature) {
//            Temp.Data4[5] = DEB_GUID;
//        }
//        else if (uSignature == uElfSignature) {
//            Temp.Data4[5] = ELF_GUID;
//        }
//        else if (uSignature == uPeSignature) {
//            Temp.Data4[5] = PE_GUID;
//        }
//        else if (uSignature == uFlvSignature) {
//            Temp.Data4[5] = FLV_GUID;
//        }
//        else if (uSignature == uLzmaSignature) {
//            Temp.Data4[5] = LZMA_GUID;
//        }
//        else if (uSignature == uLzma86Signature) {
//            Temp.Data4[5] = LZMA86_GUID;
//        }
//        else if (uSignature == uMachoSignature1) {
//            Temp.Data4[5] = MACHO_GUID;
//        }
//        else if (uSignature == uMachoSignature2) {
//            Temp.Data4[5] = MACHO_GUID;
//        }
//        else if (uSignature == uMachoSignature3) {
//            Temp.Data4[5] = MACHO_GUID;
//        }
//        else if (uSignature == uMachoSignature4) {
//            Temp.Data4[5] = MACHO_GUID;
//        }
//        else if (uSignature == uMubSignature1) {
//            Temp.Data4[5] = MUB_GUID;
//        }
//        else if (uSignature == uMubSignature2) {
//            Temp.Data4[5] = MUB_GUID;
//        }
//        else if (uSignature == uMslzSignature) {
//            Temp.Data4[5] = MSLZ_GUID;
//        }
//        else if (uSignature == uPpmdSignature) {
//            Temp.Data4[5] = PPMD_GUID;
//        }
//        else if (uSignature == uQcowSignature) {
//            Temp.Data4[5] = QCOW_GUID;
//        }
//        else if (uSignature == uRpmSignature) {
//            Temp.Data4[5] = RPM_GUID;
//        }
//        else if (uSignature == uSquashfsSignature1) {
//            Temp.Data4[5] = SQUASHFS_GUID;
//        }
//        else if (uSignature == uSquashfsSignature2) {
//            Temp.Data4[5] = SQUASHFS_GUID;
//        }
//        else if (uSignature == uSquashfsSignature3) {
//            Temp.Data4[5] = SQUASHFS_GUID;
//        }
//        else if (uSignature == uSquashfsSignature4) {
//            Temp.Data4[5] = SQUASHFS_GUID;
//        }
//        else if (uSignature == uSwfSignature) {
//            Temp.Data4[5] = SWF_GUID;
//        }
//        else if (uSignature == uSwfcSignature1) {
//            Temp.Data4[5] = SWFC_GUID;
//        }
//        else if (uSignature == uSwfcSignature2) {
//            Temp.Data4[5] = SWFC_GUID;
//        }
//        else if (uSignature == uTeSignature) {
//            Temp.Data4[5] = TE_GUID;
//        }
//        else if (uSignature == uVmdkSignature) {
//            Temp.Data4[5] = VMDK_GUID;
//        }
//        else if (uSignature == uVdiSignature) {
//            Temp.Data4[5] = VDI_GUID;
//        }
//        else if (uSignature == uVhdSignature) {
//            Temp.Data4[5] = VHD_GUID;
//        }
//        else if (uSignature == uXarSignature) {
//            Temp.Data4[5] = XAR_GUID;
//        }
//        else if (uSignature == uZSignature1) {
//            Temp.Data4[5] = Z_GUID;
//        }
//        else if (uSignature == uZSignature2) {
//            Temp.Data4[5] = Z_GUID;
//        }
//        else {
//            uBaseSignatureMask <<= 8;
//            uSignature &= uBaseSignatureMask;
//            continue;
//        }
//
//        break;
//    }
//
//    if (Temp.Data4[5] != 0) {
//        memcpy(pResult, &Temp, sizeof(Temp));
//    }
//    else {
//        FREE(pResult);
//        pResult = NULL;
//    }
//
//    return pResult;
//}
//
//ULONG IInStream_AddRef(IInStream* This) {
//    return InterlockedIncrement(&This->m_lRef);
//}
//
//HRESULT IInStream_QueryInterface
//(
//    __RPC__in IInStream* This,
//    REFIID riid,
//    void** ppv
//)
//{
//    if (IsEqualCLSID(riid, &IID_IUnknown)) {
//        *ppv = (IInStream*)This;
//        IInStream_AddRef(This);
//        return WBEM_S_NO_ERROR;
//    }
//    else {
//        return E_NOINTERFACE;
//    }
//}
//
//ULONG IInStream_Release(IInStream* This) {
//    LONG lRef = InterlockedDecrement(&This->m_lRef);
//    if (lRef == 0) {
//        FreeBuffer(This->pBuffer);
//        FREE(This->vtbl);
//        FREE(This);
//    }
//
//    return lRef;
//}
//
//UINT32 ISequentialOutStream_AddRef
//(
//    __RPC__in ISequentialOutStream* This
//)
//{
//    return InterlockedIncrement(&This->m_lRef);
//}
//
//HRESULT ISequentialOutStream_QueryInterface
//(
//    __RPC__in ISequentialOutStream* This,
//    REFIID riid,
//    void** ppv
//)
//{
//    if (IsEqualCLSID(riid, &IID_IUnknown)) {
//        *ppv = (ISequentialOutStream*)This;
//        ISequentialOutStream_AddRef(This);
//        return WBEM_S_NO_ERROR;
//    }
//    else {
//        return E_NOINTERFACE;
//    }
//}
//
//UINT32 ISequentialOutStream_Release
//(
//    __RPC__in ISequentialOutStream* This
//)
//{
//    LONG lRef = InterlockedDecrement(&This->m_lRef);
//    if (lRef == 0) {
//        FREE(This->vtbl);
//        FREE(This);
//    }
//
//    return lRef;
//}
//
//HRESULT ISequentialOutStream_Write
//(
//    __RPC__in ISequentialOutStream* This,
//    LPVOID data,
//    UINT32 size,
//    PUINT32 processedSize
//)
//{
//    PBUFFER pBuffer = NULL;
//
//    if (This->pItem != NULL) {
//        pBuffer = This->pItem->pFileData;
//        memcpy(&pBuffer->pBuffer[This->dwPos], data, size);
//        This->dwPos += size;
//    }
//
//    return S_OK;
//}
//
//HRESULT IInStream_Read
//(
//    _In_ IInStream* This,
//    _In_ PBYTE pData,
//    _In_ DWORD dwSize,
//    _Out_ PDWORD pProcessedSize
//)
//{
//    DWORD dwAvailableSize = 0;
//
//    if (dwSize == 0) {
//        if (pProcessedSize != NULL) {
//            *pProcessedSize = 0;
//        }
//
//        return S_OK;
//    }
//
//    if (This->dwPos >= This->pBuffer->cbBuffer) {
//        if (pProcessedSize != NULL) {
//            *pProcessedSize = 0;
//        }
//
//        return S_OK;
//    }
//
//    dwAvailableSize = This->pBuffer->cbBuffer - This->dwPos;
//    if (dwAvailableSize < dwSize) {
//        dwSize = dwAvailableSize;
//    }
//
//    memcpy(pData, &This->pBuffer->pBuffer[This->dwPos], dwSize);
//    This->dwPos += dwSize;
//    if (pProcessedSize != NULL) {
//        *pProcessedSize = dwSize;
//    }
//
//    return S_OK;
//}
//
//HRESULT IInStream_Seek
//(
//    _In_ IInStream* This,
//    _In_ INT64 Offset,
//    _In_ UINT32 uSeekOrigin,
//    _In_ PUINT64 pNewPosition
//)
//{
//    if (uSeekOrigin == SEEK_SET) {
//        This->dwPos = Offset;
//    }
//    else if (uSeekOrigin == SEEK_CUR) {
//        This->dwPos += Offset;
//    }
//    else if (uSeekOrigin == SEEK_END) {
//        This->dwPos = This->pBuffer->cbBuffer + Offset;
//    }
//
//    if (pNewPosition != NULL) {
//        *pNewPosition = This->dwPos;
//    }
//
//    return S_OK;
//}
//
//VOID FreeItemInfo
//(
//    _In_ PITEM_INFO pItemInfo
//)
//{
//    if (pItemInfo != NULL) {
//        FreeBuffer(pItemInfo->pFileData);
//        FREE(pItemInfo->lpPath);
//        FREE(pItemInfo);
//    }
//}
//
//UINT32 IArchiveExtractCallback_AddRef
//(
//    __RPC__in IArchiveExtractCallback* This
//)
//{
//    return InterlockedIncrement(&This->m_lRef);
//}
//
//HRESULT IArchiveExtractCallback_QueryInterface
//(
//    __RPC__in IArchiveExtractCallback* This,
//    REFIID riid,
//    void** ppv
//)
//{
//    if (IsEqualCLSID(riid, &IID_IUnknown)) {
//        *ppv = (IArchiveExtractCallback*)This;
//        IArchiveExtractCallback_AddRef(This);
//        return WBEM_S_NO_ERROR;
//    }
//    else {
//        return E_NOINTERFACE;
//    }
//}
//
//UINT32 IArchiveExtractCallback_Release
//(
//    __RPC__in IArchiveExtractCallback* This
//)
//{
//    LONG lRef = InterlockedDecrement(&This->m_lRef);
//    if (lRef == 0) {
//        FREE(This->vtbl);
//        FREE(This);
//    }
//
//    return lRef;
//}
//
//HRESULT IArchiveExtractCallback_GetStream
//(
//    __RPC__in IArchiveExtractCallback* This,
//    UINT32 index,
//    ISequentialOutStream** outStream,
//    INT32 askExtractMode
//)
//{
//    ISequentialOutStream* pOutStream = NULL;
//    if (outStream != NULL) {
//        pOutStream = ALLOC(sizeof(ISequentialOutStream));
//        pOutStream->vtbl = ALLOC(sizeof(struct ISequentialOutStreamVtbl));
//        pOutStream->vtbl->AddRef = ISequentialOutStream_AddRef;
//        pOutStream->vtbl->QueryInterface = ISequentialOutStream_QueryInterface;
//        pOutStream->vtbl->Release = ISequentialOutStream_Release;
//        pOutStream->vtbl->Write = ISequentialOutStream_Write;
//        pOutStream->pItem = This->ItemList[index];
//        *outStream = pOutStream;
//    }
//
//    return S_OK;
//}
//
//HRESULT IArchiveExtractCallback_PrepareOperation
//(
//    __RPC__in IArchiveExtractCallback* This,
//    INT32 askExtractMode
//)
//{
//    return S_OK;
//}
//
//HRESULT IArchiveExtractCallback_SetOperationResult
//(
//    __RPC__in IArchiveExtractCallback* This,
//    INT32 opRes
//)
//{
//    return S_OK;
//}
//
//HRESULT IArchiveExtractCallback_SetCompleted
//(
//    __RPC__in IArchiveExtractCallback* This,
//    PUINT64 completeValue
//)
//{
//    return S_OK;
//}
//
//HRESULT IArchiveExtractCallback_SetTotal
//(
//    __RPC__in IArchiveExtractCallback* This,
//    UINT64 total
//)
//{
//    return S_OK;
//}
//
//PITEM_INFO* ExtractFromZip
//(
//    _In_ LPWSTR lpPath,
//    _In_ LPSTR lp7zDll,
//    _In_ BOOL Extract,
//    _Out_ PDWORD pdwNumberOfItems
//)
//{
//    HMODULE h7zDll = NULL;
//    CREATEOBJECT fnCreateObject = NULL;
//    GUID IID_IInArchive = { 0x23170F69, 0x40C1, 0x278A, { 0, 0, 0, 6, 0, 0x60, 0 } };
//    GUID IID_IInStream = { 0x23170F69, 0x40C1, 0x278A, { 0, 0, 0, 3, 0, 3, 0 } };
//    GUID IID_ICompressCoder = { 0x23170F69, 0x40C1, 0x278A, { 0, 0, 0, 4, 0, 5, 0 } };
//    HRESULT hResult = S_OK;
//    PBYTE pBuffer = NULL;
//    DWORD cbBuffer = 0;
//    PGUID pFormatGUID = NULL;
//    UINT64 uSignature = 0;
//    IInArchive* pInArchive = NULL;
//    DWORD dwNumberOfItems = 0;
//    IInStream* InStream = NULL;
//    UINT64 uMaxCheckStartPosition = 0;
//    DWORD i = 0;
//    PROPVARIANT ItemProperty;
//    PUINT32 pIndices = NULL;
//    IArchiveExtractCallback* pArchiveExtractCallback = NULL;
//    PITEM_INFO* ItemList = NULL;
//    BOOL IsOk = FALSE;
//    LPWSTR lpTemp = NULL;
//
//    if (lp7zDll == NULL) {
//        lp7zDll = ALLOC(0x200);
//        GetModuleFileNameA(NULL, lp7zDll, 0x200);
//        lpTemp = PathFindFileNameA(lp7zDll);
//        lpTemp[0] = '\0';
//        lstrcatA(lp7zDll, "7z.dll");
//    }
//
//    h7zDll = LoadLibraryA(lp7zDll);
//    if (h7zDll == NULL) {
//        LOG_ERROR("LoadLibraryA", GetLastError());
//        goto CLEANUP;
//    }
//
//    pBuffer = ReadFromFile(lpPath, &cbBuffer);
//    if (pBuffer == NULL) {
//        goto CLEANUP;
//    }
//
//    memcpy(&uSignature, pBuffer, sizeof(uSignature));
//    pFormatGUID = FindFormatBySignature(_byteswap_uint64(uSignature));
//    if (pFormatGUID == NULL) {
//        goto CLEANUP;
//    }
//
//    fnCreateObject = (CREATEOBJECT)GetProcAddress(h7zDll, "CreateObject");
//    hResult = fnCreateObject(pFormatGUID, &IID_IInArchive, &pInArchive);
//    if (FAILED(hResult)) {
//        LOG_ERROR("CreateObject", hResult);
//        goto CLEANUP;
//    }
//
//    InStream = ALLOC(sizeof(IInStream));
//    InStream->pBuffer = BufferMove(pBuffer, cbBuffer);
//    pBuffer = NULL;
//    if (InStream->pBuffer == NULL) {
//        goto CLEANUP;
//    }
//
//    InStream->vtbl = ALLOC(sizeof(struct IInStreamVtbl));
//    InStream->vtbl->QueryInterface = IInStream_QueryInterface;
//    InStream->vtbl->AddRef = IInStream_AddRef;
//    InStream->vtbl->Release = IInStream_Release;
//    InStream->vtbl->Read = IInStream_Read;
//    InStream->vtbl->Seek = IInStream_Seek;
//    hResult = pInArchive->vtbl->Open(pInArchive, InStream, &uMaxCheckStartPosition, NULL);
//    if (FAILED(hResult)) {
//        LOG_ERROR("pInArchive->Open", hResult);
//        goto CLEANUP;
//    }
//
//    hResult = pInArchive->vtbl->GetNumberOfItems(pInArchive, &dwNumberOfItems);
//    if (FAILED(hResult)) {
//        LOG_ERROR("pInArchive->GetNumberOfItems", hResult);
//        goto CLEANUP;
//    }
//
//    ItemList = ALLOC(sizeof(PITEM_INFO) * dwNumberOfItems);
//    pIndices = ALLOC(sizeof(UINT32) * dwNumberOfItems);
//    for (i = 0; i < dwNumberOfItems; i++) {
//        ItemList[i] = ALLOC(sizeof(ITEM_INFO));
//        pIndices[i] = i;
//
//        PropVariantInit(&ItemProperty);
//        hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 3, &ItemProperty);
//        if (FAILED(hResult)) {
//            LOG_ERROR("pInArchive->GetProperty", hResult);
//            goto CONTINUE;
//        }
//
//        if (ItemProperty.vt != VT_BSTR) {
//            PropVariantClear(&ItemProperty);
//            goto CONTINUE;
//        }
//
//        ItemList[i]->lpPath = DuplicateStrW(ItemProperty.bstrVal, 0);
//        PropVariantClear(&ItemProperty);
//        PropVariantInit(&ItemProperty);
//        hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 6, &ItemProperty);
//        if (FAILED(hResult)) {
//            LOG_ERROR("pInArchive->GetProperty", hResult);
//            goto CONTINUE;
//        }
//
//        if (ItemProperty.vt != VT_BOOL) {
//            PropVariantClear(&ItemProperty);
//            goto CONTINUE;
//        }
//
//        ItemList[i]->IsDir = ItemProperty.boolVal == VARIANT_TRUE;
//        PropVariantClear(&ItemProperty);
//        PropVariantInit(&ItemProperty);
//        hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 15, &ItemProperty);
//        if (FAILED(hResult)) {
//            LOG_ERROR("pInArchive->GetProperty", hResult);
//            goto CONTINUE;
//        }
//
//        if (ItemProperty.vt != VT_BOOL) {
//            PropVariantClear(&ItemProperty);
//            goto CONTINUE;
//        }
//
//        ItemList[i]->IsEncrypted = ItemProperty.boolVal == VARIANT_TRUE;
//        PropVariantClear(&ItemProperty);
//        PropVariantInit(&ItemProperty);
//        hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 9, &ItemProperty);
//        if (FAILED(hResult)) {
//            LOG_ERROR("pInArchive->GetProperty", hResult);
//            goto CONTINUE;
//        }
//
//        ItemList[i]->IsSymLink = (ItemProperty.uintVal & FILE_ATTRIBUTE_REPARSE_POINT) == FILE_ATTRIBUTE_REPARSE_POINT;
//        PropVariantClear(&ItemProperty);
//        if (!ItemList[i]->IsDir && !ItemList[i]->IsEncrypted) {
//            ItemList[i]->pFileData = ALLOC(sizeof(BUFFER));
//            PropVariantInit(&ItemProperty);
//            hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 7, &ItemProperty);
//            if (FAILED(hResult)) {
//                LOG_ERROR("pInArchive->GetProperty", hResult);
//                goto CONTINUE;
//            }
//
//            ItemList[i]->pFileData->cbBuffer = ItemProperty.uintVal;
//            ItemList[i]->pFileData->pBuffer = ALLOC(ItemProperty.uintVal + 1);
//            PropVariantClear(&ItemProperty);
//        }
//
//        continue;
//    CONTINUE:
//        FreeItemInfo(ItemList[i]);
//        ItemList[i] = NULL;
//    }
//
//    if (Extract) {
//        pArchiveExtractCallback = ALLOC(sizeof(IArchiveExtractCallback));
//        pArchiveExtractCallback->vtbl = ALLOC(sizeof(struct IArchiveExtractCallbackVtbl));
//        pArchiveExtractCallback->vtbl->AddRef = IArchiveExtractCallback_AddRef;
//        pArchiveExtractCallback->vtbl->QueryInterface = IArchiveExtractCallback_QueryInterface;
//        pArchiveExtractCallback->vtbl->Release = IArchiveExtractCallback_Release;
//        pArchiveExtractCallback->vtbl->GetStream = IArchiveExtractCallback_GetStream;
//        pArchiveExtractCallback->vtbl->PrepareOperation = IArchiveExtractCallback_PrepareOperation;
//        pArchiveExtractCallback->vtbl->SetOperationResult = IArchiveExtractCallback_SetOperationResult;
//        pArchiveExtractCallback->vtbl->SetCompleted = IArchiveExtractCallback_SetCompleted;
//        pArchiveExtractCallback->vtbl->SetTotal = IArchiveExtractCallback_SetTotal;
//        pArchiveExtractCallback->ItemList = ItemList;
//        pInArchive->vtbl->Extract(pInArchive, pIndices, dwNumberOfItems, 0, pArchiveExtractCallback);
//    }
//    
//    if (FAILED(hResult)) {
//        LOG_ERROR("pInArchive->Extract", hResult);
//        goto CLEANUP;
//    }
//
//    if (pdwNumberOfItems != NULL) {
//        *pdwNumberOfItems = dwNumberOfItems;
//    }
//
//    IsOk = TRUE;
//CLEANUP:
//    if (lpTemp != NULL) {
//        FREE(lp7zDll);
//    }
//
//    if (!IsOk && ItemList != NULL) {
//        for (i = 0; i < dwNumberOfItems; i++) {
//            FreeItemInfo(ItemList[i]);
//        }
//
//        FREE(ItemList);
//        ItemList = NULL;
//    }
//
//    if (pInArchive != NULL) {
//        pInArchive->vtbl->Release(pInArchive);
//    }
//
//    FREE(pIndices);
//    FREE(pFormatGUID);
//    FREE(pBuffer);
//
//    return ItemList;
//}
//
//BOOL ExtractTo
//(
//    _In_ PBUFFER pCompressedData,
//    _In_ LPWSTR lpDest
//)
//{
//    PITEM_INFO* ItemList = NULL;
//    PITEM_INFO pItem = NULL;
//    DWORD dwNumberOfItems = 0;
//    BOOL Result = FALSE;
//    LPWSTR lpZipPath = NULL;
//    LPWSTR lpTempPath = NULL;
//    DWORD i = 0;
//
//    SHCreateDirectory(NULL, lpDest);
//    if (!IsFolderExist(lpDest)) {
//        goto CLEANUP;
//    }
//
//    lpZipPath = GenerateTempPathW(NULL, L".zip", NULL);
//    if (!WriteToFile(lpZipPath, pCompressedData->pBuffer, pCompressedData->cbBuffer)) {
//        goto CLEANUP;
//    }
//
//    ItemList = ExtractFromZip(lpZipPath, NULL, TRUE, &dwNumberOfItems);
//    DeleteFileW(lpZipPath);
//    if (dwNumberOfItems == 0 || ItemList == NULL) {
//        goto CLEANUP;
//    }
//
//    for (i = 0; i < dwNumberOfItems; i++) {
//        pItem = ItemList[i];
//        lpTempPath = DuplicateStrW(lpDest, lstrlenW(pItem->lpPath) + 1);
//        if (lpTempPath[lstrlenW(lpTempPath) - 1] != L'\\') {
//            lpTempPath[lstrlenW(lpTempPath) - 1] = L'\\';
//        }
//
//        lstrcatW(lpTempPath, pItem->lpPath);
//        if (pItem->IsDir) {
//            SHCreateDirectory(NULL, lpTempPath);
//        }
//        else {
//            WriteToFile(lpTempPath, pItem->pFileData->pBuffer, pItem->pFileData->cbBuffer);
//        }
//
//        FREE(lpTempPath);
//    }
//
//CLEANUP:
//    for (i = 0; i < dwNumberOfItems; i++) {
//        FreeItemInfo(ItemList[i]);
//    }
//
//    FREE(ItemList);
//    FREE(lpZipPath);
//
//    return Result;
//}

LONG Bit7zExceptionHandler
(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    return EXCEPTION_CONTINUE_EXECUTION;
}

LPWSTR Bit7zExtract
(
    _In_ LPWSTR lpBit7z,
    _In_ LPWSTR lpArchivePath,
    _In_ LPWSTR lpDest
)
{
    WCHAR wszBit7zPath[MAX_PATH];
    LPWSTR lp7zDll = NULL;
    LPWSTR lpTemp = NULL;
    EXTRACT_ARCHIVE fnExtractArchive = NULL;
    LPWSTR lpTempDest = NULL;
    HMODULE hMod = NULL;
    PVOID pExceptionHandler = NULL;

    pExceptionHandler = AddVectoredExceptionHandler(1, Bit7zExceptionHandler);
    if (lpBit7z == NULL) {
        GetModuleFileNameW(NULL, wszBit7zPath, _countof(wszBit7zPath));
        lpTemp = PathFindFileNameW(wszBit7zPath);
        lpTemp[0] = L'\0';
        lstrcatW(wszBit7zPath, L"LogitechLcd.dll");
    }
    else {
        lstrcpyW(wszBit7zPath, lpBit7z);
    }
    
    if (!IsFileExist(wszBit7zPath)) {
        goto CLEANUP;
    }

    lp7zDll = DuplicateStrW(wszBit7zPath, 0);
    lpTemp = PathFindFileNameW(lp7zDll);
    lpTemp[0] = L'\0';
    lstrcatW(lp7zDll, L"LogiLDA.dll");
    if (!IsFileExist(lp7zDll)) {
        goto CLEANUP;
    }

    hMod = LoadLibraryW(wszBit7zPath);
    if (hMod == NULL) {
        LOG_ERROR("LoadLibraryW", GetLastError());
        goto CLEANUP;
    }

    if (lpDest == NULL) {
        lpTempDest = GenerateTempPathW(NULL, NULL, NULL);
        CreateDirectoryW(lpTempDest, NULL);
    }
    else {
        lpTempDest = DuplicateStrW(lpDest, 0);
    }

    fnExtractArchive = (EXTRACT_ARCHIVE)GetProcAddress(hMod, "LogiLcdInit");
    if (!fnExtractArchive(lp7zDll, lpArchivePath, lpTempDest)) {
        FREE(lpTempDest);
        lpTempDest = NULL;
    }

CLEANUP:
    FREE(lp7zDll);
    RemoveVectoredExceptionHandler(pExceptionHandler);

    return lpTempDest;
}

VOID FreeArchiveInfo
(
    _In_ PARCHIVE_INFO pArchiveInfo
)
{
    DWORD i = 0;
    PITEM_INFO pItem = NULL;

    if (pArchiveInfo != NULL) {
        if (pArchiveInfo->ItemList != NULL) {
            for (i = 0; i < pArchiveInfo->dwNumberOfItems; i++) {
                pItem = pArchiveInfo->ItemList[i];
                FREE(pItem->lpPath);
                FREE(pItem);
            }

            FREE(pArchiveInfo->ItemList);
        }

        FREE(pArchiveInfo);
    }
}

PARCHIVE_INFO Bit7zGetInfo
(
    _In_ LPWSTR lpBit7z,
    _In_ LPWSTR lpArchivePath
)
{
    WCHAR wszBit7zPath[MAX_PATH];
    LPWSTR lp7zDll = NULL;
    LPWSTR lpTemp = NULL;
    GET_ARCHIVE_INFO fnGetArchiveInfo = NULL;
    HMODULE hMod = NULL;
    PVOID pExceptionHandler = NULL;
    PARCHIVE_INFO pResult = NULL;

    pExceptionHandler = AddVectoredExceptionHandler(1, Bit7zExceptionHandler);
    if (lpBit7z == NULL) {
        GetModuleFileNameW(NULL, wszBit7zPath, _countof(wszBit7zPath));
        lpTemp = PathFindFileNameW(wszBit7zPath);
        lpTemp[0] = L'\0';
        lstrcatW(wszBit7zPath, L"LogitechLcd.dll");
    }
    else {
        lstrcpyW(wszBit7zPath, lpBit7z);
    }

    if (!IsFileExist(wszBit7zPath)) {
        goto CLEANUP;
    }

    lp7zDll = DuplicateStrW(wszBit7zPath, 0);
    lpTemp = PathFindFileNameW(lp7zDll);
    lpTemp[0] = L'\0';
    lstrcatW(lp7zDll, L"LogiLDA.dll");
    if (!IsFileExist(lp7zDll)) {
        goto CLEANUP;
    }

    hMod = LoadLibraryW(wszBit7zPath);
    if (hMod == NULL) {
        LOG_ERROR("LoadLibraryW", GetLastError());
        goto CLEANUP;
    }

    fnGetArchiveInfo = (GET_ARCHIVE_INFO)GetProcAddress(hMod, "LogiLcdColorResetBackgroundUDK");
    pResult = fnGetArchiveInfo(lp7zDll, lpArchivePath);
CLEANUP:
    FREE(lp7zDll);
    RemoveVectoredExceptionHandler(pExceptionHandler);

    return pResult;
}
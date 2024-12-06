#include "pch.h"

PGUID FindFormatBySignature
(
	_In_ UINT64 uSignature
)
{
    PGUID pResult = NULL;

    UINT64 uRarSignature = 0x526172211A070000; // Rar! 0x1A 0x07 0x00
    UINT64 uRar5Signature = 0x526172211A070100; // Rar! 0x1A 0x07 0x01 0x00
    UINT64 uSevenzipSignature = 0x377ABCAF271C0000; // 7z 0xBC 0xAF 0x27 0x1C
    UINT64 uBzip2Signature = 0x425A680000000000; // BZh
    UINT64 uGzipSignature = 0x1F8B080000000000; // 0x1F 0x8B 0x08
    UINT64 uWimSignature = 0x4D5357494D000000; // MSWIM 0x00 0x00 0x00
    UINT64 uXzSignature = 0xFD377A585A000000; // 0xFD 7zXZ 0x00
    UINT64 uZipSignature = 0x504B000000000000; // PK
    UINT64 uApmSignature = 0x4552000000000000; // ER
    UINT64 uArjSignature = 0x60EA000000000000; // `EA
    UINT64 uCabSignature = 0x4D53434600000000; // MSCF 0x00 0x00 0x00 0x00
    UINT64 uChmSignature = 0x4954534603000000; // ITSF 0x03
    UINT64 uCompoundSignature = 0xD0CF11E0A1B11AE1; // 0xD0 0xCF 0x11 0xE0 0xA1 0xB1 0x1A 0xE1
    UINT64 uCpioSignature1 = 0xC771000000000000; // 0xC7 q
    UINT64 uCpioSignature2 = 0x71C7000000000000; // q 0xC7
    UINT64 uCpioSignature3 = 0x3037303730000000; // 07070
    UINT64 uDebSignature = 0x213C617263683E00; // !<arch>0A
    UINT64 uElfSignature = 0x7F454C4600000000; // 0x7F ELF
    UINT64 uPeSignature = 0x4D5A000000000000; // MZ
    UINT64 uFlvSignature = 0x464C560100000000; // FLV 0x01
    UINT64 uLzmaSignature = 0x5D00000000000000; //
    UINT64 uLzma86Signature = 0x015D000000000000; //
    UINT64 uMachoSignature1 = 0xCEFAEDFE00000000; // 0xCE 0xFA 0xED 0xFE
    UINT64 uMachoSignature2 = 0xCFFAEDFE00000000; // 0xCF 0xFA 0xED 0xFE
    UINT64 uMachoSignature3 = 0xFEEDFACE00000000; // 0xFE 0xED 0xFA 0xCE
    UINT64 uMachoSignature4 = 0xFEEDFACF00000000; // 0xFE 0xED 0xFA 0xCF
    UINT64 uMubSignature1 = 0xCAFEBABE00000000; // 0xCA 0xFE 0xBA 0xBE 0x00 0x00 0x00
    UINT64 uMubSignature2 = 0xB9FAF10E00000000; // 0xB9 0xFA 0xF1 0x0E
    UINT64 uMslzSignature = 0x535A444488F02733; // SZDD 0x88 0xF0 '3
    UINT64 uPpmdSignature = 0x8FAFAC8400000000; // 0x8F 0xAF 0xAC 0x84
    UINT64 uQcowSignature = 0x514649FB00000000; // QFI 0xFB 0x00 0x00 0x00
    UINT64 uRpmSignature = 0xEDABEEDB00000000; // 0xED 0xAB 0xEE 0xDB
    UINT64 uSquashfsSignature1 = 0x7371736800000000; // sqsh
    UINT64 uSquashfsSignature2 = 0x6873717300000000; // hsqs
    UINT64 uSquashfsSignature3 = 0x7368737100000000; // shsq
    UINT64 uSquashfsSignature4 = 0x7173687300000000; // qshs
    UINT64 uSwfSignature = 0x4657530000000000; // FWS
    UINT64 uSwfcSignature1 = 0x4357530000000000; // CWS
    UINT64 uSwfcSignature2 = 0x5A57530000000000; // ZWS
    UINT64 uTeSignature = 0x565A000000000000; // VZ
    UINT64 uVmdkSignature = 0x4B444D0000000000; // KDMV
    UINT64 uVdiSignature = 0x3C3C3C2000000000; // Alternatively, 0x7F10DABE at offset 0x40
    UINT64 uVhdSignature = 0x636F6E6563746978; // conectix
    UINT64 uXarSignature = 0x78617221001C0000; // xar! 0x00 0x1C
    UINT64 uZSignature1 = 0x1F9D000000000000; // 0x1F 0x9D
    UINT64 uZSignature2 = 0x1FA0000000000000; // 0x1F 0xA0
    GUID Temp = FORMAT_GUID;
    pResult = ALLOC(sizeof(GUID));
    if (uSignature == uRarSignature) {
        Temp.Data4[5] = RAR_GUID;
    }
    else if (uSignature == uRar5Signature) {
        Temp.Data4[5] = RAR5_GUID;
    }
    else if (uSignature == uSevenzipSignature) {
        Temp.Data4[5] = SEVENZIP_GUID;
    }
    else if (uSignature == uBzip2Signature) {
        Temp.Data4[5] = BZIP2_GUID;
    }
    else if (uSignature == uGzipSignature) {
        Temp.Data4[5] = GZIP_GUID;
    }
    else if (uSignature == uWimSignature) {
        Temp.Data4[5] = WIM_GUID;
    }
    else if (uSignature == uXzSignature) {
        Temp.Data4[5] = XZ_GUID;
    }
    else if (uSignature == uZipSignature) {
        Temp.Data4[5] = ZIP_GUID;
    }
    else if (uSignature == uApmSignature) {
        Temp.Data4[5] = APM_GUID;
    }
    else if (uSignature == uArjSignature) {
        Temp.Data4[5] = ARJ_GUID;
    }
    else if (uSignature == uCabSignature) {
        Temp.Data4[5] = CAB_GUID;
    }
    else if (uSignature == uChmSignature) {
        Temp.Data4[5] = CHM_GUID;
    }
    else if (uSignature == uCompoundSignature) {
        Temp.Data4[5] = COMPOUND_GUID;
    }
    else if (uSignature == uCpioSignature1) {
        Temp.Data4[5] = CPIO_GUID;
    }
    else if (uSignature == uCpioSignature2) {
        Temp.Data4[5] = CPIO_GUID;
    }
    else if (uSignature == uCpioSignature3) {
        Temp.Data4[5] = CPIO_GUID;
    }
    else if (uSignature == uDebSignature) {
        Temp.Data4[5] = DEB_GUID;
    }
    else if (uSignature == uElfSignature) {
        Temp.Data4[5] = ELF_GUID;
    }
    else if (uSignature == uPeSignature) {
        Temp.Data4[5] = PE_GUID;
    }
    else if (uSignature == uFlvSignature) {
        Temp.Data4[5] = FLV_GUID;
    }
    else if (uSignature == uLzmaSignature) {
        Temp.Data4[5] = LZMA_GUID;
    }
    else if (uSignature == uLzma86Signature) {
        Temp.Data4[5] = LZMA86_GUID;
    }
    else if (uSignature == uMachoSignature1) {
        Temp.Data4[5] = MACHO_GUID;
    }
    else if (uSignature == uMachoSignature2) {
        Temp.Data4[5] = MACHO_GUID;
    }
    else if (uSignature == uMachoSignature3) {
        Temp.Data4[5] = MACHO_GUID;
    }
    else if (uSignature == uMachoSignature4) {
        Temp.Data4[5] = MACHO_GUID;
    }
    else if (uSignature == uMubSignature1) {
        Temp.Data4[5] = MUB_GUID;
    }
    else if (uSignature == uMubSignature2) {
        Temp.Data4[5] = MUB_GUID;
    }
    else if (uSignature == uMslzSignature) {
        Temp.Data4[5] = MSLZ_GUID;
    }
    else if (uSignature == uPpmdSignature) {
        Temp.Data4[5] = PPMD_GUID;
    }
    else if (uSignature == uQcowSignature) {
        Temp.Data4[5] = QCOW_GUID;
    }
    else if (uSignature == uRpmSignature) {
        Temp.Data4[5] = RPM_GUID;
    }
    else if (uSignature == uSquashfsSignature1) {
        Temp.Data4[5] = SQUASHFS_GUID;
    }
    else if (uSignature == uSquashfsSignature2) {
        Temp.Data4[5] = SQUASHFS_GUID;
    }
    else if (uSignature == uSquashfsSignature3) {
        Temp.Data4[5] = SQUASHFS_GUID;
    }
    else if (uSignature == uSquashfsSignature4) {
        Temp.Data4[5] = SQUASHFS_GUID;
    }
    else if (uSignature == uSwfSignature) {
        Temp.Data4[5] = SWF_GUID;
    }
    else if (uSignature == uSwfcSignature1) {
        Temp.Data4[5] = SWFC_GUID;
    }
    else if (uSignature == uSwfcSignature2) {
        Temp.Data4[5] = SWFC_GUID;
    }
    else if (uSignature == uTeSignature) {
        Temp.Data4[5] = TE_GUID;
    }
    else if (uSignature == uVmdkSignature) {
        Temp.Data4[5] = VMDK_GUID;
    }
    else if (uSignature == uVdiSignature) {
        Temp.Data4[5] = VDI_GUID;
    }
    else if (uSignature == uVhdSignature) {
        Temp.Data4[5] = VHD_GUID;
    }
    else if (uSignature == uXarSignature) {
        Temp.Data4[5] = XAR_GUID;
    }
    else if (uSignature == uZSignature1) {
        Temp.Data4[5] = Z_GUID;
    }
    else if (uSignature == uZSignature2) {
        Temp.Data4[5] = Z_GUID;
    }
    else {
        FREE(pResult);
        return NULL;
    }

    memcpy(pResult, &Temp, sizeof(Temp));
    return pResult;
}

UINT32 IInStream_AddRef(IInStream* This) {
    return InterlockedIncrement(&This->m_lRef);
}

HRESULT IInStream_QueryInterface(IInStream* This, REFIID riid, void** ppv) {
    if (IsEqualCLSID(riid, &IID_IUnknown)) {
        *ppv = (IInStream*)This;
        IInStream_AddRef(This);
        return WBEM_S_NO_ERROR;
    }
    else {
        return E_NOINTERFACE;
    }
}

VOID DestroyInStream(IInStream* This) {
    if (This->pBuffer != NULL) {
        FreeBuffer(This->pBuffer);
        This->pBuffer = NULL;
    }
}

UINT32 IInStream_Release(IInStream* This) {
    LONG lRef = InterlockedDecrement(&This->m_lRef);
    if (lRef == 0) {
        DestroyInStream(This);
    }

    return lRef;
}

HRESULT IInStream_Read
(
    _In_ IInStream* This,
    _In_ PBYTE pData,
    _In_ DWORD dwSize,
    _Out_ PDWORD pProcessedSize
)
{
    DWORD dwAvailableSize = 0;

    if (dwSize == 0) {
        if (pProcessedSize != NULL) {
            *pProcessedSize = 0;
        }

        return S_OK;
    }

    if (This->dwPos >= This->pBuffer->cbBuffer) {
        if (pProcessedSize != NULL) {
            *pProcessedSize = 0;
        }

        return S_OK;
    }

    dwAvailableSize = This->pBuffer->cbBuffer - This->dwPos;
    if (dwAvailableSize < dwSize) {
        dwSize = dwAvailableSize;
    }

    memcpy(pData, &This->pBuffer->pBuffer[This->dwPos], dwSize);
    This->dwPos += dwSize;
    if (pProcessedSize != NULL) {
        *pProcessedSize = dwSize;
    }

    return S_OK;
}

HRESULT IInStream_Seek
(
    _In_ IInStream* This,
    _In_ INT64 Offset,
    _In_ UINT32 uSeekOrigin,
    _In_ PUINT64 pNewPosition
)
{
    if (uSeekOrigin == SEEK_SET) {
        This->dwPos = Offset;
    }
    else if (uSeekOrigin == SEEK_CUR) {
        This->dwPos += Offset;
    }
    else if (uSeekOrigin == SEEK_END) {
        This->dwPos = This->pBuffer->cbBuffer + Offset;
    }

    if (pNewPosition != NULL) {
        *pNewPosition = This->dwPos;
    }

    return S_OK;
}
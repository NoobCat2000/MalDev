#include "pch.h"

LPWSTR GetDnsReverseNameFromAddress
(
	_In_ PIP_ADDRESS pAddress
)
{
	LPWSTR lpResult = NULL;
	DWORD i = 0;

	lpResult = ALLOC(0x80 * sizeof(WCHAR));
	if (pAddress->Type == IPV4_NETWORK_TYPE) {
		wsprintfW(lpResult, L"%d.%d.%d.%d.in-addr.arpa.", pAddress->InAddr.s_impno, pAddress->InAddr.s_lh, pAddress->InAddr.s_host, pAddress->InAddr.s_net);
	}
	else {
		for (i = sizeof(IN6_ADDR) - 1; i >= 0; i--) {
			wsprintfW(&lpResult[lstrlenW(lpResult)], L"%x.%x.", pAddress->In6Addr.s6_addr[i] & 0xF, (pAddress->In6Addr.s6_addr[i] >> 4) & 0xF);
		}

		lpResult = StrCatExW(lpResult, L"ip6.arpa.");
	}

	return lpResult;
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

PBYTE CreateDnsMessageBuffer
(
	_In_ LPWSTR lpMessage,
	_In_ USHORT uMessageType,
	_In_ USHORT uMessageID,
	_Out_ PDWORD pcbBuffer
)
{
	PBYTE pDnsBuffer = NULL;
	DWORD cbDnsBuffer = 0x1000;

	pDnsBuffer = ALLOC(cbDnsBuffer);
	if (!DnsWriteQuestionToBuffer_W(pDnsBuffer, &cbDnsBuffer, lpMessage, uMessageType, uMessageID, TRUE)) {
		pDnsBuffer = REALLOC(pDnsBuffer, cbDnsBuffer);
		if (!DnsWriteQuestionToBuffer_W(pDnsBuffer, &cbDnsBuffer, lpMessage, uMessageType, uMessageID, TRUE)) {
			FREE(pDnsBuffer);
			pDnsBuffer = NULL;
			return NULL;
		}
	}

	if (pcbBuffer != NULL) {
		*pcbBuffer = cbDnsBuffer;
	}

	return pDnsBuffer;
}

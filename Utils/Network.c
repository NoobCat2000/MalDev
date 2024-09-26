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

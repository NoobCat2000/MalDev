#pragma once

LPWSTR GetDnsReverseNameFromAddress
(
	_In_ PIP_ADDRESS pAddress
);

LPSTR SocketAddressToStr
(
	_In_ LPSOCKADDR lpSockAddr
);;
#pragma once

typedef struct _OTP_DATA
{
	DWORD dwDigits;
	DWORD dwInterval;
	UINT64 uCount;

	/*OTPType method;
	COTP_ALGO algo;
	COTP_TIME time;*/

	LPSTR lpBase32Secret;
} OTP_DATA, *POTP_DATA;

UINT64 GetOtpNow
(
	_In_ POTP_DATA pOtpData
);

POTP_DATA OtpInit
(
	_In_ DWORD dwInterval,
	_In_ UINT64 uCount,
	_In_ DWORD dwDigits,
	_In_ LPSTR lpBase32Secret
);
#pragma once

typedef enum _LSA_USER_ACCOUNT_TYPE
{
	UnknownUserAccountType,
	LocalUserAccountType,
	PrimaryDomainUserAccountType,
	ExternalDomainUserAccountType,
	LocalConnectedUserAccountType,
	AADUserAccountType,
	InternetUserAccountType,
	MSAUserAccountType
} LSA_USER_ACCOUNT_TYPE, *PLSA_USER_ACCOUNT_TYPE;

#define SYSTEM_IDLE_PROCESS_ID ((HANDLE)0)
/** The PID of the system process. */
#define SYSTEM_PROCESS_ID ((HANDLE)4)
typedef NTSTATUS(WINAPI* LSALOOKUPUSERACCOUNTTYPE)(PSID, PLSA_USER_ACCOUNT_TYPE);

typedef struct _TOKEN_GROUP_INFO {
	CHAR szName[0x100];
	CHAR szStatus[0x20];
	CHAR szDesc[0x80];
	CHAR szSID[0x40];
	CHAR szMandatoryLabel[0x20];
} TOKEN_GROUP_INFO, *PTOKEN_GROUP_INFO;

typedef struct _TOKEN_INFO {
	PTOKEN_GROUP_INFO pTokenGroupsInfo;
	PTOKEN_PRIVILEGES pPrivileges;
	DWORD dwGroupCount;
	BOOL IsElevated;
	TOKEN_ELEVATION_TYPE ElevationType;
	DWORD dwSession;
	LPSTR lpUserName;
	LPSTR lpUserSID;
	LPSTR lpIntegrityLevel;
} TOKEN_INFO, *PTOKEN_INFO;

typedef struct _PROCESS_INFO {
	LPSTR lpImageFilePath;
	LPSTR lpCommandLine;
	LPSTR lpCurrentDirectory;
	DWORD dwPID;
	DWORD dwPPID;
	LPSTR lpMitigationDesc;
	LPSTR lpVersion;
	LPSTR lpCompanyName;
	LPSTR lpImageDesc;
	LPSTR lpProductName;
	BOOL IsWow64;
} PROCESS_INFO, *PPROCESS_INFO;

BOOL Run
(
	_In_ LPWSTR* Argv,
	_In_ DWORD dwArgc,
	_Out_ PHANDLE phProcess
);

DWORD GetProcessIdByName
(
	_In_ LPWSTR lpProcessName
);

HANDLE CreateProcessAndStealToken
(
	_In_ LPWSTR lpFilePath
);

HANDLE SetTokenWithUiAccess
(
	_In_ HANDLE hToken
);

HANDLE GetUiAccessToken(VOID);

NTSTATUS IsProcessElevated
(
	_In_ ULONG ProcessId,
	_Out_ PBOOL Elevated
);

VOID ReadOutputFromProcess
(
	_In_ HANDLE hPipeRead,
	_In_ HANDLE hProcess,
	_Out_ PBYTE* pBufferPointer,
	_Out_ PDWORD pdwSize
);

BOOL CreateProcessAndGetOutput
(
	_In_ LPWSTR lpCommandLine,
	_Out_ PBYTE* pOutput,
	_Out_ PDWORD pdwSize
);

BOOL CreateProcessWithDesktop
(
	_In_ LPWSTR lpCommandLine,
	_In_ LPWSTR lpDesktopName
);

BOOL AreProcessesRunning
(
	_In_ LPWSTR* pNameList,
	_In_ DWORD dwCount,
	_In_ DWORD dwMin
);

BOOL CheckForBlackListProcess(VOID);

LPSTR GetCurrentProcessUserSID(VOID);

LPSTR GetCurrentProcessGroupSID(VOID);

LPSTR DescribeProcessMitigation
(
	_In_ HANDLE hProcess
);

LPSTR GetSecurityAttributeFlagsString
(
	_In_ ULONG uFlags
);

PTOKEN_GROUPS GetTokenGroups
(
	_In_ HANDLE hToken
);

LPSTR LookupNameOfSid
(
	_In_ PSID pSid,
	_In_ BOOL IncludeDomain
);

BOOL IsTokenElevated
(
	_In_ HANDLE hToken
);

BOOL IsTokenAppContainer
(
	_In_ HANDLE hToken
);

LPSTR GetTokenIntegrityLevel
(
	_In_ HANDLE hToken
);

TOKEN_ELEVATION_TYPE GetTokenElevationType
(
	_In_ HANDLE hToken
);

PTOKEN_USER GetTokenUser
(
	_In_ HANDLE hToken
);

PTOKEN_GROUP_INFO GetTokenGroupsInfo
(
	_In_ HANDLE hToken,
	_Out_ PDWORD pGroupCount
);

ULONG GetTokenSessionID
(
	_In_ HANDLE hToken
);

PTOKEN_INFO GetTokenInfo
(
	_In_ HANDLE hProc
);

PTOKEN_SECURITY_ATTRIBUTES_INFORMATION GetTokenSecurityAttributes
(
	_In_ HANDLE hToken
);

PTOKEN_PRIVILEGES GetTokenPrivileges
(
	_In_ HANDLE hToken
);

LPVOID GetProcessPebAddr
(
	_In_ HANDLE hProc
);

ULONG_PTR GetProcessPebAddr32
(
	_In_ HANDLE hProc
);

LPSTR GetProcessImagePath
(
	_In_ HANDLE hProc
);

LPSTR GetProcessCurrentDirectory
(
	_In_ HANDLE hProc
);

LPSTR GetProcessCommandLine
(
	_In_ HANDLE hProc
);

PSYSTEM_PROCESS_INFORMATION EnumProcess
(
	_Out_ PDWORD pcbOutput
);

PPROCESS_BASIC_INFORMATION GetProcessBasicInfo
(
	_In_ HANDLE hProc
);

VOID FreeTokenInfo
(
	_In_ PTOKEN_INFO pTokenInfo
);

LPSTR GetProcessImageFileNameWin32
(
	_In_ HANDLE hProc
);

LPSTR LookupNameOfSid
(
	_In_ PSID pSid,
	_In_ BOOL IncludeDomain
);

BOOL IsMemoryReadable
(
	_In_ LPVOID lpAddress
);
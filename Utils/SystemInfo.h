#pragma once

#define WINDOWS_ANCIENT 0
#define WINDOWS_XP 51 // August, 2001
#define WINDOWS_SERVER_2003 52 // April, 2003
#define WINDOWS_VISTA 60 // November, 2006
#define WINDOWS_7 61 // July, 2009
#define WINDOWS_8 62 // August, 2012
#define WINDOWS_8_1 63 // August, 2013
#define WINDOWS_10 100 // TH1 // July, 2015
#define WINDOWS_10_TH2 101 // November, 2015
#define WINDOWS_10_RS1 102 // August, 2016
#define WINDOWS_10_RS2 103 // April, 2017
#define WINDOWS_10_RS3 104 // October, 2017
#define WINDOWS_10_RS4 105 // April, 2018
#define WINDOWS_10_RS5 106 // November, 2018
#define WINDOWS_10_19H1 107 // May, 2019
#define WINDOWS_10_19H2 108 // November, 2019
#define WINDOWS_10_20H1 109 // May, 2020
#define WINDOWS_10_20H2 110 // October, 2020
#define WINDOWS_10_21H1 111 // May, 2021
#define WINDOWS_10_21H2 112 // November, 2021
#define WINDOWS_10_22H2 113 // October, 2022
#define WINDOWS_11 114 // October, 2021
#define WINDOWS_11_22H2 115 // September, 2022
#define WINDOWS_11_23H2 116 // October, 2023
#define WINDOWS_11_24H2 117 // TBA
#define WINDOWS_NEW ULONG_MAX

typedef DWORD(WINAPI* GETEXTENDEDTCPTABLE)(PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);
typedef DWORD(WINAPI* GETEXTENDEDUDPTABLE)(PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);
typedef ULONG(WINAPI* INTERNALGETBOUNDTCPENDPOINTTABLE)(PVOID*, PVOID, ULONG);
typedef ULONG(WINAPI* INTERNALGETBOUNDTCP6ENDPOINTTABLE)(PVOID*, PVOID, ULONG);
#define NETWORK_OWNER_INFO_SIZE 16
#define IPV4_NETWORK_TYPE 0x1
#define IPV6_NETWORK_TYPE 0x2
#define NETWORK_TYPE_MASK 0x3

#define TCP_PROTOCOL_TYPE 0x10
#define UDP_PROTOCOL_TYPE 0x20
#define PROTOCOL_TYPE_MASK 0x30

#define NO_NETWORK_PROTOCOL 0x0
#define TCP4_NETWORK_PROTOCOL (IPV4_NETWORK_TYPE | TCP_PROTOCOL_TYPE)
#define TCP6_NETWORK_PROTOCOL (IPV6_NETWORK_TYPE | TCP_PROTOCOL_TYPE)
#define UDP4_NETWORK_PROTOCOL (IPV4_NETWORK_TYPE | UDP_PROTOCOL_TYPE)
#define UDP6_NETWORK_PROTOCOL (IPV6_NETWORK_TYPE | UDP_PROTOCOL_TYPE)

typedef struct _IP_ADDRESS
{
    ULONG Type;
    union
    {
        ULONG Ipv4;
        IN_ADDR InAddr;
        UCHAR Ipv6[16];
        IN6_ADDR In6Addr;
    };
} IP_ADDRESS, *PIP_ADDRESS;

typedef struct _IP_ENDPOINT
{
    IP_ADDRESS Address;
    ULONG Port;
} IP_ENDPOINT, *PIP_ENDPOINT;

typedef struct _NETWORK_CONNECTION
{
    ULONG uProtocolType;
    IP_ENDPOINT LocalEndpoint;
    IP_ENDPOINT RemoteEndpoint;
    DWORD State;
    HANDLE ProcessId;
    LARGE_INTEGER CreateTime;
    ULONGLONG OwnerInfo[NETWORK_OWNER_INFO_SIZE];
    ULONG uLocalScopeId;
    ULONG uRemoteScopeId;
} NETWORK_CONNECTION, *PNETWORK_CONNECTION;

BOOL IsSystemLock(VOID);

LPSTR GetHostUUID(VOID);

LPSTR GetUserSID
(
    _In_ LPSTR lpUserName
);

LPSTR GetCurrentUserSID(VOID);

LPSTR GetComputerUserName(VOID);

LPSTR GetHostName(VOID);

LPSTR GetPrimaryDnsSuffix(VOID);

BOOL GetOsVersion
(
    PRTL_OSVERSIONINFOW lpVersionInformation
);

DWORD GetWindowsVersionEx(VOID);

PNETWORK_CONNECTION GetNetworkConnections
(
    _Out_ PDWORD pNumberOfConnections
);

DWORD NumberOfProcessors(VOID);
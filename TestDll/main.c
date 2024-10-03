// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

//HHOOK callWndHook = NULL;
//HMODULE dllInstance;
//
//FILE* outFile;
//
//void logToOutFile(const char* format, ...) {
//    va_list args;
//    va_start(args, format);
//
//    vfprintf_s(outFile, format, args);
//    fflush(outFile);
//
//    va_end(args);
//}
//
//LRESULT CALLBACK CallWndProc(int code, WPARAM wParam, LPARAM lParam) {
//    BOOL isUpdate = FALSE;
//    BOOL isMonitoring = FALSE;
//    CWPSTRUCT* msg = (CWPSTRUCT*)lParam;
//    WCHAR wszWindowTitle[MAX_PATH];
//    WCHAR wszMsg[0x400];
//    DWORD dwProcessId = 0;
//
//    if (code < HC_ACTION)
//    {
//        goto END;
//    }
//
//    GetWindowThreadProcessId(msg->hwnd, &dwProcessId);
//    if (dwProcessId == 21572 && msg->message > WM_MOUSEFIRST && msg->message < WM_MOUSEHWHEEL) {
//         GetWindowTextW(msg->hwnd, wszWindowTitle, MAX_PATH);
//         _wfopen_s(&outFile, L"C:\\Users\\Admin\\Desktop\\log.txt", L"a");
//         fwprintf(outFile, L"PID %d: %lls, %d\n", dwProcessId, wszWindowTitle, msg->message);
//         fclose(outFile);
//    }
//
//END:
//    return CallNextHookEx(callWndHook, code, wParam, lParam);
//}
//
//HHOOK InstallHook()
//{
//    callWndHook = SetWindowsHookExW(WH_CALLWNDPROC, CallWndProc, dllInstance, 0);
//    if (!callWndHook)
//    {
//        return NULL;
//    }
//
//    return callWndHook;
//}
//

void test79(void) {
    PNETWORK_CONNECTION pConnections = NULL;
    PNETWORK_CONNECTION pConnectionEnrty = NULL;
    DWORD dwNumberOfConnections = 0;
    DWORD i = 0;

    pConnections = GetNetworkConnections(&dwNumberOfConnections);
    for (i = 0; i < dwNumberOfConnections; i++) {
        pConnectionEnrty = &pConnections[i];
        PrintFormatA("uProtocolType: %d\n", pConnectionEnrty->uProtocolType);
        PrintFormatA("Ipv4: %s\n", pConnectionEnrty->LocalEndpoint.Address.Ipv4);
    }
}

LPSTR SocketAddressToStr
(
    _In_ LPSOCKADDR lpSockAddr
)
{
    return NULL;
}

BOOL APIENTRY DllMain
(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        /*MessageBoxA(NULL, "Hello World", "Title", MB_OK);
        dllInstance = hModule;*/
        SocketAddressToStr(NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


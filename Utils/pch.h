// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include <phnt_windows.h>
#include <phnt.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <wininet.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <combaseapi.h>
#include <Wbemidl.h>
#include <Wbemcli.h>
#include <shlobj_core.h>
#include <MSTask.h>
#include <taskschd.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <WinTrust.h>
#include <compressapi.h>

#include "framework.h"
#include "Utils.h"
#include "EventSink.h"

#endif //PCH_H

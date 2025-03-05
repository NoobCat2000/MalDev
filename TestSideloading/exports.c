#include "pch.h"

DWORD ConfuseEmulation(void)
{
    DWORD i = 0;
    DWORD j = 0;
    DWORD k = 0;
    WCHAR wszKernel32[MAX_PATH];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    FILETIME CreationTime;
    FILETIME LastAccessTime;
    FILETIME LastWriteTime;

    for (i = 0; i < 0x10000; i++) {
        for (j = 0; j < 0x1000; j++) {
            k++;
            k ^= 0x20;
            k &= i;
            k %= (i + 1);
        }

        ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\kernel32.dll", wszKernel32, _countof(wszKernel32));
        if (IsFileExist(wszKernel32)) {
            hFile = CreateFileW(wszKernel32, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            k += GetFileSize(hFile, NULL);
            SecureZeroMemory(&CreationTime, sizeof(CreationTime));
            SecureZeroMemory(&LastAccessTime, sizeof(LastAccessTime));
            SecureZeroMemory(&LastWriteTime, sizeof(LastWriteTime));
            GetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime);
            k += CreationTime.dwLowDateTime;
            k += CreationTime.dwHighDateTime;
            k += LastAccessTime.dwLowDateTime;
            k += LastAccessTime.dwHighDateTime;
            k += LastWriteTime.dwLowDateTime;
            k += LastWriteTime.dwHighDateTime;
            CloseHandle(hFile);
            k += 0x200;
        }
        else {
            k -= 0x200;
        }

    }

    return k;
}

DWORD AddOfficeProduct(void)
{
    return ConfuseEmulation();
}

DWORD AddOfficeProductEx(void)
{
    return ConfuseEmulation();
}

DWORD ApplyCloudPolicy(void)
{
    return ConfuseEmulation();
}

DWORD ApplyCloudPolicyForIdentity(void)
{
    return ConfuseEmulation();
}

DWORD C2rVersion(void)
{
    return ConfuseEmulation();
}

DWORD CheckProcessForCorruption(void)
{
    return ConfuseEmulation();
}

DWORD CleanupWindowsDefenderFirewallRulesForOffice(void)
{
    return ConfuseEmulation();
}

DWORD ClearPropertyBagValue(void)
{
    return ConfuseEmulation();
}

DWORD CollectFileInformation(void)
{
    return ConfuseEmulation();
}

DWORD DeleteAFOScheduledTask(void)
{
    return ConfuseEmulation();
}

DWORD DetectWindowsDefenderFirewallRulesForOffice(void)
{
    return ConfuseEmulation();
}

DWORD EnableUpdate(void)
{
    return ConfuseEmulation();
}

DWORD EnsureConnection(void)
{
    return ConfuseEmulation();
}

DWORD EnsurePerpetualLicensesFolderExists(void)
{
    return ConfuseEmulation();
}

DWORD FetchDBSLicense(void)
{
    return ConfuseEmulation();
}

DWORD GetInstalledProducts(void)
{
    return ConfuseEmulation();
}

DWORD GetInstalledProductsEx(void)
{
    return ConfuseEmulation();
}

DWORD GetPackageRoot(void)
{
    return ConfuseEmulation();
}

DWORD GetProperty(void)
{
    return ConfuseEmulation();
}

DWORD GetPropertyEx(void)
{
    return ConfuseEmulation();
}

DWORD GetStatusValue(void)
{
    return ConfuseEmulation();
}

DWORD GetStatusValueEx(void)
{
    return ConfuseEmulation();
}

DWORD GetTotalProgress(void)
{
    return ConfuseEmulation();
}

DWORD GetUpdateStatus(void)
{
    return ConfuseEmulation();
}

DWORD HandleError(void)
{
    return ConfuseEmulation();
}

DWORD HandleErrorEx(void)
{
    return ConfuseEmulation();
}

DWORD HandleScheduledHeartbeat(void)
{
    return ConfuseEmulation();
}

DWORD HandleScheduledHeartbeatEx(void)
{
    return ConfuseEmulation();
}

DWORD HrActivate(void)
{
    return ConfuseEmulation();
}

DWORD HrActivateEx(void)
{
    return ConfuseEmulation();
}

DWORD HrApplyUpdatesNow(void)
{
    return ConfuseEmulation();
}

DWORD HrApplyUpdatesNowEx(void)
{
    return ConfuseEmulation();
}

DWORD HrBeginUpdatesDiscoveryPeriod(void)
{
    return ConfuseEmulation();
}

DWORD HrBeginUpdatesDiscoveryPeriodEx(void)
{
    return ConfuseEmulation();
}

DWORD HrDownloadUpdatesNow(void)
{
    return ConfuseEmulation();
}

DWORD HrDownloadUpdatesNowEx(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAppVFlight(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesCOMManaged(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesEnabled(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesEnabledEx(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesFromAdminSource(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesFromAdminSourceEx(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesLate(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesLateEx(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesReadyForDownload(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesReadyForDownloadEx(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesReadyToApply(void)
{
    return ConfuseEmulation();
}

DWORD HrGetAreUpdatesReadyToApplyEx(void)
{
    return ConfuseEmulation();
}

DWORD HrGetChannelIdForDisplay(void)
{
    return ConfuseEmulation();
}

DWORD HrGetClientFolder(void)
{
    return ConfuseEmulation();
}

DWORD HrGetContainerInstallCommand(void)
{
    return ConfuseEmulation();
}

DWORD HrGetDeviceBasedLicensing(void)
{
    return ConfuseEmulation();
}

DWORD HrGetExecutingScenario(void)
{
    return ConfuseEmulation();
}

DWORD HrGetInstallationPath(void)
{
    return ConfuseEmulation();
}

DWORD HrGetPendingModifyOfficeProducts(void)
{
    return ConfuseEmulation();
}

DWORD HrGetPendingUpdateDeadline(void)
{
    return ConfuseEmulation();
}

DWORD HrGetPendingUpdateDeadlineEx(void)
{
    return ConfuseEmulation();
}

DWORD HrInstallProtectedGraceLicense(void)
{
    return ConfuseEmulation();
}

DWORD HrModifyOfficeProducts(void)
{
    return ConfuseEmulation();
}

DWORD HrRefreshState(void)
{
    return ConfuseEmulation();
}

DWORD HrRegisterForRealtimeExitReporting(void)
{
    return ConfuseEmulation();
}

DWORD HrSetAreUpdatesEnabled(void)
{
    return ConfuseEmulation();
}

DWORD HrSetAreUpdatesEnabledEx(void)
{
    return ConfuseEmulation();
}

DWORD HrSetAreUpdatesFromAdminSource(void)
{
    return ConfuseEmulation();
}

DWORD HrSetAreUpdatesFromAdminSourceEx(void)
{
    return ConfuseEmulation();
}

DWORD HrSetPrivacySettings(void)
{
    return ConfuseEmulation();
}

DWORD HrUpdateLicensingStateData(void)
{
    return ConfuseEmulation();
}

DWORD HrUpdateNow(void)
{
    return ConfuseEmulation();
}

DWORD HrUpdateNowEx(void)
{
    return ConfuseEmulation();
}

DWORD HrUpdateNowWithParameters(void)
{
    return ConfuseEmulation();
}

DWORD InstallProofOfPurchase(void)
{
    return ConfuseEmulation();
}

DWORD InstallProofOfPurchaseEx(void)
{
    return ConfuseEmulation();
}

DWORD IsClick2Run(void)
{
    return ConfuseEmulation();
}

DWORD IsFileInVirtualFolder(void)
{
    return ConfuseEmulation();
}

DWORD IsOSPPReady(void)
{
    return ConfuseEmulation();
}

DWORD IsOSPPReadyEx(void)
{
    return ConfuseEmulation();
}

DWORD IsRepairRequired(void)
{
    return ConfuseEmulation();
}

DWORD IsRepairRequiredEx(void)
{
    return ConfuseEmulation();
}

DWORD IsRoaming(void)
{
    return ConfuseEmulation();
}

DWORD IsStreaming(void)
{
    return ConfuseEmulation();
}

DWORD Launch(void)
{
    return ConfuseEmulation();
}

DWORD LicenseRepair(void)
{
    return ConfuseEmulation();
}

DWORD MigrateOSPPToSPP(void)
{
    return ConfuseEmulation();
}

DWORD OverridePolicy(void)
{
    return ConfuseEmulation();
}

DWORD ReArm(void)
{
    return ConfuseEmulation();
}

DWORD Repair(void)
{
    return ConfuseEmulation();
}

DWORD RepairEx(void)
{
    return ConfuseEmulation();
}

DWORD SetProperty(void)
{
    return ConfuseEmulation();
}

DWORD SetPropertyBagToken(void)
{
    return ConfuseEmulation();
}

DWORD SetTenantAssociationKey(void)
{
    return ConfuseEmulation();
}

DWORD SetUpdateBranch(void)
{
    return ConfuseEmulation();
}

DWORD SetUpdateUrl(void)
{
    return ConfuseEmulation();
}

DWORD SetUpdateUrlSetByUser(void)
{
    return ConfuseEmulation();
}

DWORD StartFB(void)
{
    return ConfuseEmulation();
}

DWORD StartScenario(void)
{
    return ConfuseEmulation();
}

DWORD UninstallProofOfPurchase(void)
{
    return ConfuseEmulation();
}

DWORD UninstallProofOfPurchaseEx(void)
{
    return ConfuseEmulation();
}
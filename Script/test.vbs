Dim fso
Dim LogiPath
Dim RunCmd As Boolean

Set fso = CreateObject("Scripting.FileSystemObject")
Set WshShell = WScript.CreateObject("WScript.Shell")
LogiPath = WshShell.ExpandEnvironmentStrings("%APPDATA%\com.logi")
If (fso.FolderExists(LogiPath)) Then
    Set folder = fso.GetFolder(LogiPath)
    Set files = folder.Files
    RunCmd = 0
    For each item In files
        fullName = LogiPath & "\" & item.Name
        If InStr(item.Name, ".txt") <> 0 Then
            RunCmd = -1
            Set reader = fso.OpenTextFile(fullName, 1, True, 0)
            command = reader.ReadLine
            reader.Close
            fso.DeleteFile(fullName)
            WshShell.Run(command)
        End If
    Next

    If RunCmd = False Then
        WshShell.Run(%s)
    End If
End If
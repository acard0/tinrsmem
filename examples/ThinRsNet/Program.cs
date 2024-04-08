using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ThinRsNet;

class Program
{
    static int SomeValue = 59478578;
    static void Main(string[] args)
    {
        var api = new RsMemoryApi();
        api.OpenProcess((uint)Environment.ProcessId);

        var address = api.AoBScan(IntoAoBPattern(BitConverter.GetBytes(SomeValue), true, true), true, false)
            .First();

        api.WriteBytes(address, BitConverter.GetBytes(31));
        var read = BitConverter.ToInt32(api.ReadBytes(address, 4));

        Debug.Assert(read == 31);
    }

    private static string IntoAoBPattern(byte[] data, bool asHex, bool separate)
    {
        var str = data.Aggregate("", (current, @byte) => current + (separate ? " " : "") + (asHex ? @byte.ToString("X2") : @byte.ToString("D2")));
        return str.TrimStart(' ');
    }
}

public class RsMemoryApi
{
    public uint ProcessId { get; set; }

    private IntPtr? _targetHandle;

    public RsMemoryApi()
    {
        __set_log_level(0);
    }

    public bool OpenProcess(uint pid)
    {
        if (ProcessId == pid)
            return true;

        if (_targetHandle.HasValue)
            CloseProcess();

        if (__attach(pid).IsError())
            return false;

        ProcessId = pid;
        unsafe { _targetHandle = new IntPtr(__attach(pid).result); }
        return true;
    }

    public void CloseProcess()
    {
        __detach(ProcessId);
        _targetHandle = null;
    }

    public IEnumerable<long> AoBScan(string query, bool writable, bool executable)
    {
        if (!CheckHandle()) return Array.Empty<long>();

        return __aob_query(_targetHandle!.Value, ByteBuffer.FromString(query), false, false, writable, executable)
            .Unwrap()
            .Select(e => (long)e);
    }

    public byte[] ReadBytes(long address, int length)
    {
        if (!CheckHandle()) return Array.Empty<byte>();

        try
        {
            var buffer = Marshal.AllocHGlobal(length);
            var readLenght = __read_memory(_targetHandle!.Value, (IntPtr)address, buffer, length);
            var result = new byte[length];
            Marshal.Copy(buffer, result, 0, length);
            Marshal.FreeHGlobal(buffer);

            if (readLenght != length)
                return Array.Empty<byte>();

            return result;
        }
        catch {}

        return Array.Empty<byte>();
    }

    public void WriteBuffer(long address, ByteBuffer buffer)
    {
        if (!CheckHandle()) return;

        try
        {
            var result = __write_memory(_targetHandle!.Value, (IntPtr)address, buffer);

            if (result.IsError())
                throw new Exception(result.GetError());
        }
        catch { }
    }

    public void WriteBytes(long address, byte[] bytes)
    {
        if (!CheckHandle()) return;

        WriteBuffer(address, ByteBuffer.FromBytes(bytes));
    }

    private bool CheckHandle()
    {
        if (_targetHandle == null)
            //throw new Exception("Target handle is not set.");
            return false;

        return true;
    }

    [DllImport("rsmem", EntryPoint = "attach", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern CallResult<IntPtr> __attach(ulong pid);

    [DllImport("rsmem", EntryPoint = "detach", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern CallResult<IntPtr> __detach(ulong pid);

    [DllImport("rsmem", EntryPoint = "aob_query", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern CallResult<IEnumerable<IntPtr>> __aob_query(IntPtr target_handle, ByteBuffer pattern, bool mapped, bool readable, bool writable, bool executable);

    [DllImport("rsmem", EntryPoint = "collect_pages", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern CallResult<IEnumerable<MemoryPageInfo>> __collect_pages(IntPtr target_handle);

    [DllImport("rsmem", EntryPoint = "write_memory", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern CallResult<nuint> __write_memory(IntPtr target_handle, IntPtr address, ByteBuffer buffer);

    [DllImport("rsmem", EntryPoint = "read_bytes", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern CallResult<IEnumerable<byte>> __read_bytes(IntPtr target_handle, IntPtr address, nint size);

    [DllImport("rsmem", EntryPoint = "read_memory", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern nint __read_memory(IntPtr target_handle, IntPtr address, IntPtr destination, nint size);


    [DllImport("rsmem", EntryPoint = "log_to_file", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern void __log_to_file(ulong level);

    [DllImport("rsmem", EntryPoint = "set_log_level", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    static unsafe extern void __set_log_level(ulong level);
}

[StructLayout(LayoutKind.Sequential)]
public struct MemoryPageInfo
{
    public UIntPtr BaseAddress;
    public nuint Size;
    public uint Flags;
    public string Type;
    public string Protect;
    public string? Usage;
    public UIntPtr Alloc_base;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CallResult<T>
{
#pragma warning disable CS8500 // This takes the address of, gets the size of, or declares a pointer to a managed type
    public void* result;
#pragma warning restore CS8500 // This takes the address of, gets the size of, or declares a pointer to a managed type
    public IntPtr error;
}

public static class CallResultExtensions
{
    public static bool IsError<T>(this CallResult<T> result)
    {
        return result.error != IntPtr.Zero;
    }

    public static string GetError<T>(this CallResult<T> result)
    {
        return Marshal.PtrToStringAnsi(result.error)!;
    }

    public static IEnumerable<T> Unwrap<T>(this CallResult<IEnumerable<T>> result)
    {
        if (result.IsError())
        {
            throw new Exception(result.GetError());
        }

        unsafe
        {
            var buffer = Marshal.PtrToStructure<ByteBuffer>((IntPtr)result.result);
            var elements = new List<T>();
            var size = (nint)Marshal.SizeOf<T>();
            for (nint i = 0; i < buffer.Count; i++)
            {
                var element = Marshal.PtrToStructure<T>((IntPtr)(buffer.Address + (i * size)));
                elements.Add(element!);
            }

            return elements;
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct ByteBuffer
{
    public IntPtr Address; // pointer to first elem
    public nint Count;
    public nint Capacity;
    public nint Size;

    public readonly nint ElementSize => Size == 0 ? 0 : Size / Count;

    private ByteBuffer(IntPtr address, nint count, nint capacity, nint size)
    {
        Address = address;
        Count = count;
        Capacity = capacity;
        Size = size;
    }

    public static ByteBuffer Empty => new();

    public static ByteBuffer FromStringArray(params string[] strings)
    {
        var inputs = strings.ToArray();
        var size = inputs.Length * IntPtr.Size;
        var inputsPtr = Marshal.AllocCoTaskMem(size);

        for (int i = 0; i < inputs.Length; i++)
        {
            Marshal.WriteIntPtr(inputsPtr, i * IntPtr.Size, Marshal.StringToCoTaskMemAnsi(inputs[i]));
        }

        return FromRaw(inputsPtr, strings.Length, strings.Length, size);
    }

    public static ByteBuffer FromRaw(IntPtr address, nint count, nint capacity, nint size)
    {
        return new ByteBuffer(address, count, capacity, size);
    }

    public static ByteBuffer FromBytes(byte[] bytes)
    {
        var ptr = Marshal.UnsafeAddrOfPinnedArrayElement(bytes, 0);
        return FromRaw(ptr, bytes.Length, bytes.Length, bytes.Length * sizeof(byte));
    }

    public static ByteBuffer FromString(string str)
    {
        var bytes = Encoding.UTF8.GetBytes(str);
        return FromBytes(bytes);
    }
}


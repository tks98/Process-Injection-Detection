using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Process_Injection_Detection
{
    class Program
    {
        public static ProcessThreadCollection RunningThreads { get; private set; }

        static void Main(string[] args)
        {
            ProcessExaminer processExaminer = new ProcessExaminer();
            //processExaminer.PrintAllProcessesModules();

            Process targetProcess = processExaminer.GetProcessesByName(".", args[0]);
            if (targetProcess == null)
            {
                Console.WriteLine("Could not retrieve target process, is it running?");
                return;
            }

            processExaminer.PrintRegions(targetProcess);

           
            List<Module> modules = processExaminer.CollectModules(targetProcess);

            foreach (Module module in modules)
            {
                DumpModule(module);
            }

            Console.WriteLine("Dumping Threads\n");
            ProcessThreadCollection RunningThreads = targetProcess.Threads;
            foreach (ProcessThread thread in RunningThreads)
            {  
                Console.WriteLine(thread.Id);
                Console.WriteLine(thread.ThreadState);
            } 

        }

        private static void DumpModule(Module module)
        {
            Console.WriteLine("Module Name:" + module.ModuleName);
            Console.WriteLine("Base Address" + module.BaseAddress);
            Console.WriteLine("Module Size:" + module.Size);
            Console.WriteLine("\n");
            return;
        }
    }
}


class ProcessExaminer
{
    public Process GetProcessesByName(string machine, string processName)
    {
        ArrayList processList = new ArrayList();
        Process[] runningProcesses = Process.GetProcesses(machine);
        Process targetProcess = null;

        foreach (Process current in runningProcesses)
        {
            // Check for a match. 
            if (current.ProcessName == processName)
            {
                processList.Add(current);
                targetProcess = current;
                break;
            } // Dispose of any we're not keeping 
            else
            {
                current.Dispose();
            }
        }
        return targetProcess;
    }

    public void PrintRegions(Process process)
    {
        long MaxAddress = 0x7fffffff;
        long address = 0;
        do
        {
            Native.MEMORY_BASIC_INFORMATION m;
            int result = Native.VirtualQueryEx(process.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(Native.MEMORY_BASIC_INFORMATION)));
            Console.WriteLine("{0}-{1} : {2} bytes perm={3}", m.BaseAddress, (uint)m.BaseAddress + (uint)m.RegionSize - 1, m.RegionSize, m.AllocationProtect);
            if (address == (long)m.BaseAddress + (long)m.RegionSize)
                break;
            address = (long)m.BaseAddress + (long)m.RegionSize;
        } while (address <= MaxAddress);
    }

    public void PrintAllProcessesModules()
    {
        Process[] runningProcesses = Process.GetProcesses(".");
        foreach (Process current in runningProcesses)
        {
            Console.WriteLine(current.ProcessName);
            try
            {
                List<Module> modules = CollectModules(current);
                foreach (Module module in modules)
                {
                    Console.WriteLine(module.ModuleName);
                }
            }

            catch (Exception e)
            {
                Console.WriteLine(current.ProcessName);
                Console.WriteLine(e);
            }

            Console.WriteLine("\n");
        }


    }



    public List<Module> CollectModules(Process process)
    {
        List<Module> collectedModules = new List<Module>();

        IntPtr[] modulePointers = new IntPtr[0];
        int bytesNeeded = 0;

        // Determine number of modules
        if (!Native.EnumProcessModulesEx(process.Handle, modulePointers, 0, out bytesNeeded, (uint)Native.ModuleFilter.ListModulesAll))
        {
            return collectedModules;
        }

        int totalNumberofModules = bytesNeeded / IntPtr.Size;
        modulePointers = new IntPtr[totalNumberofModules];

        // Collect modules from the process
        if (Native.EnumProcessModulesEx(process.Handle, modulePointers, bytesNeeded, out bytesNeeded, (uint)Native.ModuleFilter.ListModulesAll))
        {
            for (int index = 0; index < totalNumberofModules; index++)
            {
                StringBuilder moduleFilePath = new StringBuilder(1024);
                Native.GetModuleFileNameEx(process.Handle, modulePointers[index], moduleFilePath, (uint)(moduleFilePath.Capacity));

                string moduleName = Path.GetFileName(moduleFilePath.ToString());
                Native.ModuleInformation moduleInformation = new Native.ModuleInformation();
                Native.GetModuleInformation(process.Handle, modulePointers[index], out moduleInformation, (uint)(IntPtr.Size * (modulePointers.Length)));

                // Convert to a normalized module and add it to our list
                Module module = new Module(moduleName, moduleInformation.lpBaseOfDll, moduleInformation.SizeOfImage);
                collectedModules.Add(module);
            }
        }

        return collectedModules;
    }
}




public class Native
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ModuleInformation
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    internal enum ModuleFilter
    {
        ListModulesDefault = 0x0,
        ListModules32Bit = 0x01,
        ListModules64Bit = 0x02,
        ListModulesAll = 0x03,
    }
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public AllocationProtectEnum AllocationProtect;
        public IntPtr RegionSize;
        public StateEnum State;
        public AllocationProtectEnum Protect;
        public TypeEnum Type;
    }

    public enum AllocationProtectEnum : uint
    {
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }

    public enum StateEnum : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_FREE = 0x10000,
        MEM_RESERVE = 0x2000
    }

    public enum TypeEnum : uint
    {
        MEM_IMAGE = 0x1000000,
        MEM_MAPPED = 0x40000,
        MEM_PRIVATE = 0x20000
    }




    [DllImport("psapi.dll")]
    public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll")]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out ModuleInformation lpmodinfo, uint cb);

    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);


}

public class Module
{
    public Module(string moduleName, IntPtr baseAddress, uint size)
    {
        this.ModuleName = moduleName;
        this.BaseAddress = baseAddress;
        this.Size = size;
    }

    public string ModuleName { get; set; }
    public IntPtr BaseAddress { get; set; }
    public uint Size { get; set; }
}


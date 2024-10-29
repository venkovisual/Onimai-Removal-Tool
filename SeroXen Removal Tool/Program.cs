using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using static Onimai_Removal_Tool.Native;

namespace Onimai_Removal_Tool
{
    internal class Program
    {
        static unsafe void Main(string[] args)
        {
            if (!IsAdmin())
            {
                Console.WriteLine("Onimai Removal Tool - 1.7.4");
                Console.WriteLine("");
                if (!Confirm("[ ] Onimai Removal tool NEEDS Administrator to remove Onimai please do so.", true))
                    return;

                try
                {
                    Restart(true);
                }
                catch
                {
                    Console.WriteLine("[X] Failed to exit automatically please press any key to continue...");
                    Console.ReadKey(true);
                }

                return;
            }

            try
            {
                using (TaskService ts = new TaskService())
                {
                    if (ts.RootFolder.Tasks.Exists(@"ORT Task") == false)
                    {
                        DialogResult dialogResult = MessageBox.Show(@"To start Onimai Removal process you need to Restart your PC Would you like to do that now?", @"Onimai Removal Tool", MessageBoxButtons.YesNo);
                        if (dialogResult == DialogResult.Yes)
                        {
                            TaskDefinition td = ts.NewTask();
                            td.Triggers.Add(new LogonTrigger());
                            td.Actions.Add(new ExecAction(Application.ExecutablePath, @"--force", null));
                            td.Settings.DisallowStartIfOnBatteries = false;
                            td.Principal.RunLevel = TaskRunLevel.Highest;
                            ts.RootFolder.RegisterTaskDefinition(@"ORT Task", td);

                            ProcessStartInfo startInfo = new ProcessStartInfo();
                            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                            startInfo.UseShellExecute = true;
                            startInfo.Arguments = @"/r /f /t 0";
                            startInfo.FileName = @"shutdown.exe";
                            Process.Start(startInfo);
                            Environment.Exit(-1);
                        }
                        else if (dialogResult == DialogResult.No)
                        {
                            Environment.Exit(-1);
                        }
                    }
                    else
                    {
                        ts.RootFolder.DeleteTask(@"ORT Task", false);
                    }
                }
            }
            catch
            {
            }

            Process.EnterDebugMode();

            var iocs = ScanIOCs();

            if (iocs.Length > 0)
            {
                Console.WriteLine("Onimai Removal Tool - 1.7.4");
                Console.WriteLine("");
                Console.WriteLine("\n[+] Found Onimai");
                Console.WriteLine("\n[+] Starting Removal Process");

                if (iocs.Contains(IndicatorOfCompromise.Process))
                {
                    IOCCleaner.CleanProcesses();
                }

                foreach (var ioc in iocs)
                {
                    switch (ioc)
                    {
                        case IndicatorOfCompromise.Files:
                            IOCCleaner.CleanFiles();
                            break;

                        case IndicatorOfCompromise.ScheduledTask:
                            IOCCleaner.CleanScheduledTask();
                            break;

                        case IndicatorOfCompromise.Environment:
                            IOCCleaner.CleanEnvironment();
                            break;

                        case IndicatorOfCompromise.Registry:
                            IOCCleaner.CleanRegistry();
                            break;
                    }
                }

                Console.WriteLine("[+] Cleaning up Files");
                Console.WriteLine("[+] Cleaning up Onimai on Startup");
                Console.WriteLine("[+] Cleaning up Computer Enviroment");
                Console.WriteLine("[+] Cleaning up Registry");

                Console.WriteLine("[+] Restart your PC to remove the rootkit Completely.\n");
                Console.WriteLine("[ ] Press any key to exit...");
            }
            else
            {
                Console.WriteLine("[ ] Looks like your safe");
            }

            Console.ReadKey(true);
        }

        static bool Confirm(string prompt, bool @default = false)
        {
            while (true)
            {
                Console.Write($"{prompt} [{(@default ? "Y" : "y")}/{(@default ? "n" : "N")}] ");

                var key = Console.ReadKey(true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine(@default ? "Yes" : "No");
                    return @default;
                }

                switch (key.KeyChar.ToString().ToLower())
                {
                    case "y":
                        Console.WriteLine("Yes");
                        return true;

                    case "n":
                        Console.WriteLine("No");
                        return false;

                    default:
                        Console.WriteLine();
                        break;
                }
            }
        }

        static bool IsAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void Restart(bool runas = false, string args = "")
        {
            Process.Start(new ProcessStartInfo()
            {
                FileName = Assembly.GetExecutingAssembly().Location,
                Arguments = args,
                Verb = runas ? "runas" : "",
            });

            Environment.Exit(0);
        }

        static IndicatorOfCompromise[] ScanIOCs()
        {
            var list = new List<IndicatorOfCompromise>();

            if (IOCDetector.RootkitIOC())
            {
                Console.WriteLine("[+] Found possible Rootkit just double checking");
                Console.WriteLine("[+] Located Rootkit attempting to Detatch");
                list.Add(IndicatorOfCompromise.Rootkit);

                IOCCleaner.DetachRootkit();
            }

            if (IOCDetector.FilesIOC())
            {
                Console.WriteLine("[+] Found possible traces of Onimai just double checking");
                Console.WriteLine("[+] Located Onimai Files");
                list.Add(IndicatorOfCompromise.Files);
            }

            if (IOCDetector.ScheduledTaskIOC())
            {
                Console.WriteLine("[+] Found Onimai in task schedular just double checking");
                Console.WriteLine("[+] Located Onimai Startup Method");
                list.Add(IndicatorOfCompromise.ScheduledTask);
            }

            if (IOCDetector.RegistryIOC())
            {
                Console.WriteLine("[+] Located Onimai in Registry");
                list.Add(IndicatorOfCompromise.Registry);
            }

            if (IOCDetector.EnvironmentIOC())
            {
                Console.WriteLine("[+] Located Onimai in system Enviroment");
                list.Add(IndicatorOfCompromise.Environment);
            }

            if (IOCDetector.ProcessesIOC())
            {
                Console.WriteLine("[ ] Onimai is currently active on this system");
                list.Add(IndicatorOfCompromise.Process);
            }

            return list.ToArray();
        }
    }

    internal enum IndicatorOfCompromise
    {
        Files,
        ScheduledTask,
        Registry,
        Environment,
        Process,
        Rootkit
    }

    internal static class IOCDetector
    {
        public static bool FilesIOC()
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            var mstha = Path.Combine(windows, "$nya-mshta.exe");
            var cmd = Path.Combine(windows, "$nya-cmd.exe");
            var powershell = Path.Combine(windows, "$nya-powershell.exe");
            var mshta2 = Path.Combine(windows, "$rbx-mshta.exe");
            var cmd2 = Path.Combine(windows, "$rbx-cmd.exe");
            var powershell2 = Path.Combine(windows, "$rbx-powershell.exe");
            var mshta3 = Path.Combine(windows, "$cnt-mshta.exe");
            var cmd3 = Path.Combine(windows, "$cnt-cmd.exe");
            var powershell3 = Path.Combine(windows, "$cnt-powershell");

            var any = Directory.GetFiles(windows)
                .Any(filename => filename.ToLower().StartsWith("$nya")
                     || filename.ToLower().StartsWith("$rbx")
                     || filename.ToLower().StartsWith("$cnt")
                     && filename.ToLower().EndsWith(".exe"));


            return File.Exists(mstha) || File.Exists(cmd) || File.Exists(powershell) || any;
        }

        public static bool ScheduledTaskIOC()
        {
            using var sched = new TaskService();

            if (sched.RootFolder.Tasks.Any(task =>
                task.Name.ToLower().StartsWith("$nya") ||
                task.Name.ToLower().StartsWith("$rbx") ||
                task.Name.ToLower().StartsWith("$cnt")))
            {
                return true;
            }


            return false;
        }

        public unsafe static bool RootkitIOC()
        {
            var module = Native.GetModuleHandle(null);
            if (module == IntPtr.Zero)
                return false;

            var signature = *(ushort*)(module.ToInt64() + 64);

            return signature == 0x7260;
        }

        public static bool RegistryIOC()
        {
            return Registry.LocalMachine.OpenSubKey("SOFTWARE").GetValueNames()
            .Any(name => name.ToLower().StartsWith("$nya") ||
                 name.ToLower().StartsWith("$rbx") ||
                 name.ToLower().StartsWith("$cnt"));

        }

        public static bool EnvironmentIOC()
        {
            foreach (var key in Environment.GetEnvironmentVariables().Keys)
            {
                var keyString = key.ToString().ToLower();
                if (keyString.StartsWith("$nya") ||
                    keyString.StartsWith("$rbx") ||
                    keyString.StartsWith("$cnt"))
                {
                    return true;
                }
            }


            return false;
        }

        public static bool ProcessesIOC()
        {
            var names = new string[] { "$nya-cmd", "$nya-mshta", "$nya-powershell", "$rbx-cmd", "$rbx-mshta", "$rbx-powershell" };

            return Process.GetProcesses().Any(proc => names.Contains(proc.ProcessName));
        }
    }

    internal static class IOCCleaner
    {
        public static void CleanFiles()
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var files = Directory.GetFiles(windows, "*.exe")
                .Where(filename => filename.ToLower().StartsWith(Path.Combine(windows, "$nya")) ||
                                   filename.ToLower().StartsWith(Path.Combine(windows, "$rbx")) ||
                                   filename.ToLower().StartsWith(Path.Combine(windows, "$cnt")))
                .ToArray();


            Console.WriteLine("[+] Removed onimai files");

            foreach (var file in files)
            {
                Thread.Sleep(1000);
                try
                {
                    File.Delete(file);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ ] Failed to delete file {file}: {ex.Message}");
                    Console.WriteLine($"[ ] You may have to manually remove it");
                }
            }
        }

        public static void CleanScheduledTask()
        {
            using var sched = new TaskService();

            Console.WriteLine("[+] Removed scheduled task / startup");

            var tasks = sched.AllTasks
    .Where(task => task.Name.ToLower().StartsWith("$nya") ||
                   task.Name.ToLower().StartsWith("$rbx") ||
                   task.Name.ToLower().StartsWith("$cnt"))
    .ToList();


            foreach (var task in tasks)
                task.Folder.DeleteTask(task.Name);
        }

        public static void CleanRegistry()
        {
            using var key = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
            var names = key.GetValueNames()
                .Where(name => name.ToLower().StartsWith("$nya") ||
                               name.ToLower().StartsWith("$rbx") ||
                               name.ToLower().StartsWith("$cnt"))
                .ToList();


            Console.WriteLine("[+] Removed registry value");

            foreach (var name in names)
                key.DeleteValue(name);
        }

        public static void CleanEnvironment()
        {
            Console.WriteLine("[+] Removed environmental variables");

            foreach (var key in Environment.GetEnvironmentVariables().Keys)
            {
                var keyString = key.ToString().ToLower();
                if (keyString.StartsWith("$nya") ||
                    keyString.StartsWith("$rbx") ||
                    keyString.StartsWith("$cnt"))
                {
                    Environment.SetEnvironmentVariable(keyString, null, EnvironmentVariableTarget.Machine);
                    Environment.SetEnvironmentVariable(keyString, null, EnvironmentVariableTarget.Process);
                    Console.WriteLine($"[+] Removed variable: {keyString}");
                }
            }
        }


        public static void CleanProcesses()
        {
            var names = new string[] { "$nya-cmd", "$nya-mshta", "$nya-powershell", "$rbx-cmd", "$rbx-mshta", "$rbx-powershell" };
            var processes = Process.GetProcesses().Where(proc => names.Contains(proc.ProcessName));

            int value = 0;

            Console.WriteLine("[+] Terminating processes");

            foreach (var process in processes)
                Native.NtSetInformationProcess(process.Handle, 0x1D, ref value, sizeof(int));

            foreach (var process in processes)
                process.Kill();
        }

        public static void DetachRootkit()
        {
            Console.WriteLine("[+] Reloading ntdll.dll");
            Unhook.UnhookDll("ntdll.dll");
            Console.WriteLine("[+] Reloading kernel32.dll");
            Unhook.UnhookDll("kernel32.dll");
            Console.WriteLine("[+] Reloading advapi32.dll");
            Unhook.UnhookDll("advapi32.dll");
            Console.WriteLine("[+] Reloading sechost.dll");
            Unhook.UnhookDll("sechost.dll");
            Console.WriteLine("[+] Reloading taskschd.dll");
            Unhook.UnhookDll("taskschd.dll");
            Console.WriteLine("[+] Reloading pdh.dll");
            Unhook.UnhookDll("pdh.dll");
            Console.WriteLine("[+] Detatched Rootkit");
        }
    }

    internal static class Native
    {
        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x20007;

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, long dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcess(
           string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
           IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
    }
}

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Labs_OS4
{
    public partial class Form1 : Form
    {
        private struct PROCESS_MEMORY_COUNTERS
        {
            public uint cb;
            public uint PageFaultCount;
            public UInt64 PeakWorkingSetSize;
            public UInt64 WorkingSetSize;
            public UInt64 QuotaPeakPagedPoolUsage;
            public UInt64 QuotaPagedPoolUsage;
            public UInt64 QuotaPeakNonPagedPoolUsage;
            public UInt64 QuotaNonPagedPoolUsage;
            public UInt64 PagefileUsage;
            public UInt64 PeakPagefileUsage;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            All = (HeapList | Process | Thread | Module),
            Inherit = 0x80000000,
            NoHeaps = 0x40000000

        }
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };
        public struct THREADENTRY32
        {

            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ThreadID;
            internal UInt32 th32OwnerProcessID;
            internal UInt32 tpBasePri;
            internal UInt32 tpDeltaPri;
            internal UInt32 dwFlags;
        }
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);
        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess((uint)flags, false, (uint)proc.Id);
        }
        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool GetProcessMemoryInfo(IntPtr hProcess, out PROCESS_MEMORY_COUNTERS counters, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);
        [DllImport("kernel32.dll")]
        static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);
        [DllImport("kernel32.dll")]
        static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);
        [DllImport("kernel32.dll")]
        static extern uint GetCurrentProcessId();
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        enum ThreadPriority
        {
            THREAD_MODE_BACKGROUND_BEGIN = 0x00010000,
            THREAD_MODE_BACKGROUND_END = 0x00020000,
            THREAD_PRIORITY_ABOVE_NORMAL = 1,
            THREAD_PRIORITY_BELOW_NORMAL = -1,
            THREAD_PRIORITY_HIGHEST = 2,
            THREAD_PRIORITY_IDLE = -15,
            THREAD_PRIORITY_LOWEST = -2,
            THREAD_PRIORITY_NORMAL = 0,
            THREAD_PRIORITY_TIME_CRITICAL = 15
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
        uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
        [Flags]
        public enum DuplicateOptions : uint
        {
            DUPLICATE_CLOSE_SOURCE = (0x00000001),// Closes the source handle. This occurs regardless of any error status returned.
            DUPLICATE_SAME_ACCESS = (0x00000002), //Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
        }
        [DllImport("psapi.dll")]
        static extern uint GetModuleFileNameEx(int hProcess, int hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] int nSize);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] in string lpModuleName);
        [StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public struct MODULEENTRY32
        {
            internal uint dwSize;
            internal uint th32ModuleID;
            internal uint th32ProcessID;
            internal uint GlblcntUsage;
            internal uint ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }
        [DllImport("kernel32.dll")]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
        [DllImport("kernel32.dll")]
        static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        public Form1()
        {
            InitializeComponent();
            int amount_of_threads = 0;
            int amount_of_process = 0;
            IntPtr h;
            IntPtr h2;
            PROCESS_MEMORY_COUNTERS pmc;
            int cb;
            IntPtr hSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.Process, 0);
            PROCESSENTRY32 lppe = new PROCESSENTRY32();
            THREADENTRY32 lpte = new THREADENTRY32();
            StringBuilder modName = new StringBuilder("ABC",255);
            if (hSnapshot.Equals(0))
            {
                Close();
            }
            lppe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
            if (Process32First(hSnapshot, ref lppe))
            {
                while (Process32Next(hSnapshot, ref lppe))
                {
                    amount_of_process++;
                    dataGridView1.Rows.Add(amount_of_process.ToString(), Path.GetFileName(lppe.szExeFile), lppe.th32ProcessID.ToString(), ((int)lppe.cntThreads).ToString(), "Unknown");
                    amount_of_threads += (int)lppe.cntThreads;
                    h = OpenProcess(0x00000400, false, lppe.th32ProcessID);
                    if ((int)h != 0)
                    {
                        cb = (int)Marshal.SizeOf(typeof(PROCESS_MEMORY_COUNTERS));
                        pmc = new PROCESS_MEMORY_COUNTERS();
                        pmc.cb = (uint)cb;
                        if (GetProcessMemoryInfo(h, out pmc, (uint)cb))
                        {
                            dataGridView1.Rows[(int)amount_of_process - 1].Cells[4].Value = (pmc.WorkingSetSize / 1024).ToString() + " kb";
                        }
                        else
                        {
                            dataGridView1.Rows[(int)amount_of_process - 1].Cells[4].Value = "Unknown";
                            //FreeMen(pmc);
                            CloseHandle(h);
                        }
                    }
                    else
                    {
                        dataGridView1.Rows[(int)amount_of_process - 1].Cells[4].Value = "Unknown";
                    }
                }
                label1.Text = "Всего потоков: " + amount_of_threads.ToString();

            }
            lpte.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
            hSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.Thread, 0);
            if (hSnapshot.Equals(0))
            {
                Close();
            }
            amount_of_threads = 0;
            if (Thread32First(hSnapshot, ref lpte))
            {
                while (Thread32Next(hSnapshot, ref lpte))
                {
                    amount_of_threads++;
                    dataGridView2.Rows.Add(amount_of_threads.ToString(), lpte.th32ThreadID.ToString(), lpte.th32OwnerProcessID.ToString(), "Uknown", "Unknown");
                    switch ((int)lpte.tpBasePri)
                    {
                        case 4:
                            dataGridView2[3, amount_of_threads].Value = "ожидающий";
                            break;
                        case 8:
                            dataGridView2[3, amount_of_threads].Value = "нормальный";
                            break;
                        case 13:
                            dataGridView2[3, amount_of_threads].Value = "высокий";
                            break;
                        case 24:
                            dataGridView2[3, amount_of_threads].Value = "реального времени";
                            break;
                        default:
                            dataGridView2[3, amount_of_threads].Value = "Unknown";
                            break;
                    }
                    switch ((int)lpte.tpDeltaPri)
                    {
                        case -15:
                            dataGridView2[4, amount_of_threads].Value = "Idle";
                            break;
                        case -2:
                            dataGridView2[4, amount_of_threads].Value = "the lowest";
                            break;
                        case -1:
                            dataGridView2[4, amount_of_threads].Value = "delow normal";
                            break;
                        case -0:
                            dataGridView2[4, amount_of_threads].Value = "normal";
                            break;
                        case 1:
                            dataGridView2[4, amount_of_threads].Value = "above normal";
                            break;
                        case 2:
                            dataGridView2[4, amount_of_threads].Value = "the highest";
                            break;
                        case 15:
                            dataGridView2[4, amount_of_threads].Value = "time critical";
                            break;
                        default:
                            dataGridView2[4, amount_of_threads].Value = "Unknown";
                            break;

                    }
                }
            }
            label5.Text = "ID процесса: " + GetCurrentProcessId();
            label6.Text = "Псевдодескриптор: " + GetCurrentProcess();
            DuplicateHandle((IntPtr)GetCurrentProcess(), (IntPtr)GetCurrentProcess(), (IntPtr)GetCurrentProcess(), out h, 0, false, (uint)DuplicateOptions.DUPLICATE_SAME_ACCESS);
            h2 = OpenProcess((uint)ProcessAccessFlags.All, false, GetCurrentProcessId());
            label7.Text = "Копия дескриптора текущего процесса: " + h2.ToString();
            CloseHandle(h);
            CloseHandle(h2);
            GetModuleFileNameEx(0, 0, modName, 255);

            label9.Text = modName.ToString();
            label10.Text = "Дескриптор модуля: " + GetModuleHandle(label9.Text).ToString();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            richTextBox1.Clear();
            MODULEENTRY32 lpme = new MODULEENTRY32();
            lpme.dwSize = (uint)Marshal.SizeOf(lpme);
            int id = int.Parse(dataGridView1.CurrentRow.Cells[2].Value.ToString());
            IntPtr hSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.Module, (uint)id);
            Module32First(hSnapshot, ref lpme);
            Encoding CN = Encoding.Unicode;
            Encoding unicode = Encoding.ASCII;
            do
            {
                byte[] unicodeBytes = CN.GetBytes(lpme.szModule);
                string CNString = unicode.GetString(unicodeBytes);
                richTextBox1.Text += CNString + Environment.NewLine;

            } while (Module32Next(hSnapshot, ref lpme));
            CloseHandle(hSnapshot);
        }
    }
}


<#
One-line installer for the ice3tier node on Windows (x86_64). Run it in a PowerShell opened with "Run as administrator".

Install the node as a system service (it runs in the background and starts at boot):
  irm https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1 | iex

Install, join and start in one command:
  $env:I3T_TOKEN = '<TOKEN>'; irm https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1 | iex

Settings are environment variables, set before the command. They apply to one run: the script clears them.
  I3T_TOKEN          Enrollment token; joins the network and starts the service
  I3T_CAN_RELAY=1    Declare relay capability when joining
  I3T_CAN_EXIT=1     Declare exit capability when joining
  I3T_VERSION        Install a specific release tag (e.g. v0.1.34) instead of the latest
  I3T_RELEASE_BASE   Release base URL (https:// required; default: GitHub Releases)
  I3T_RELEASE_KEY    Trust an extra/custom Ed25519 release signing public key (43-char base64url)
  I3T_FROM           Take i3t.exe and wintun.dll from a local directory instead of downloading
  I3T_UNINSTALL=1    Remove the service and the program
  I3T_PURGE=1        With I3T_UNINSTALL, also delete the node's key and settings

What it installs:
  %ProgramFiles%\ice3tier   i3t.exe and wintun.dll (the virtual adapter's driver), added to the machine PATH
  %ProgramData%\i3t         the node's key and settings, readable by SYSTEM and Administrators only; the log is i3t.log
  service "i3t"             starts at boot, restarts when it fails; `i3t join` starts it
#>

# Everything runs in a child scope: piped into iex, this script shares the caller's session and must not leave its
# variables, functions or preferences behind. That is also why the settings are not parameters: iex would create them
# in the caller's scope. Failures are thrown, never `exit`: that would close the caller's window.
& {
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell 5.1 draws a progress bar that slows downloads to a crawl.
    $ProgressPreference = 'SilentlyContinue'

    $service = 'i3t'
    $asset = 'i3t-windows-x86_64.zip'
    # Pinned release signing public key (must match PROJECT_KEYS in crates/i3t-update/src/trust.rs).
    $releasePublicKey = 'kWB8NBoJtLGX7mZwXgMSZ1C8RkUDpkdOphusy_JhEk0'
    $allowedFiles = @('i3t.exe', 'wintun.dll', 'wintun-LICENSE.txt')
    # A 32-bit PowerShell on 64-bit Windows sees "Program Files (x86)" as ProgramFiles.
    $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $dir = Join-Path $programFiles 'ice3tier'
    $exe = Join-Path $dir 'i3t.exe'
    $state = Join-Path $env:ProgramData 'i3t'

    $token = $env:I3T_TOKEN
    $relay = $env:I3T_CAN_RELAY -eq '1'
    $canExit = $env:I3T_CAN_EXIT -eq '1'
    $version = $env:I3T_VERSION
    $releaseBase = $env:I3T_RELEASE_BASE
    $releaseKey = $env:I3T_RELEASE_KEY
    $from = $env:I3T_FROM
    $removing = $env:I3T_UNINSTALL -eq '1'
    $purging = $env:I3T_PURGE -eq '1'
    # One run only: left set, I3T_UNINSTALL would turn the next install in this window into an uninstall.
    foreach ($name in 'I3T_TOKEN', 'I3T_CAN_RELAY', 'I3T_CAN_EXIT', 'I3T_VERSION', 'I3T_RELEASE_BASE', 'I3T_RELEASE_KEY', 'I3T_FROM', 'I3T_UNINSTALL', 'I3T_PURGE') {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }

    function Say([string]$text) {
        Write-Host "==> $text"
    }

    # C# 5.0 compatible helper (Windows PowerShell 5.1 & PowerShell 7+):
    # - RFC 8032 Ed25519 manifest signature verification matching crates/i3t-crypto & crates/i3t-update
    # - Atomic protected-DACL directory creation (CreateDirectoryW + SDDL) eliminating New-Item -> icacls TOCTOU
    # - Reparse-point-safe & owner/DACL-checked validation and recursive deletion for %ProgramData%\i3t
    if (-not ('Ice3tier.Installer.Native' -as [type])) {
        $nativeSource = @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ice3tier.Installer
{
    public static class Native
    {
        // Protected DACL: Owner = BUILTIN\Administrators, only SYSTEM and Administrators have Full Control.
        private const string StateDirSddl = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        private const string StateFileSddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
        private const string SidSystem = "S-1-5-18";
        private const string SidAdministrators = "S-1-5-32-544";

        private const uint SDDL_REVISION_1 = 1;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_PATH_NOT_FOUND = 3;
        private const int ERROR_ALREADY_EXISTS = 183;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
        private const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

        private const uint READ_CONTROL = 0x00020000;
        private const uint WRITE_DAC = 0x00040000;
        private const uint FILE_SHARE_ALL = 0x00000007;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        private const uint SE_FILE_OBJECT = 1;
        private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;

        // Any write/modify/append/delete/take-ownership/write-DAC/generic-write/generic-all right.
        private const int UntrustedWriteMask = 0x500D0156;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public FILETIME ftCreationTime;
            public FILETIME ftLastAccessTime;
            public FILETIME ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectoryW(string lpPathName, ref SECURITY_ATTRIBUTES lpSecurityAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RemoveDirectoryW(string lpPathName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributesW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileAttributesW(string lpFileName, uint dwFileAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            out IntPtr SecurityDescriptor,
            out uint SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool lpbDaclPresent,
            out IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] out bool lpbDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetKernelObjectSecurity(
            SafeFileHandle Handle,
            uint RequestedInformation,
            byte[] pSecurityDescriptor,
            uint nLength,
            out uint lpnLengthNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint SetSecurityInfo(
            SafeFileHandle handle,
            uint ObjectType,
            uint SecurityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl);

        private static bool IsTrustedSid(string sid)
        {
            return string.Equals(sid, SidSystem, StringComparison.OrdinalIgnoreCase)
                || string.Equals(sid, SidAdministrators, StringComparison.OrdinalIgnoreCase);
        }

        private static RawSecurityDescriptor ReadSecurityDescriptor(SafeFileHandle handle)
        {
            uint needed = 0;
            GetKernelObjectSecurity(handle, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, null, 0, out needed);
            int err = Marshal.GetLastWin32Error();
            if (err != ERROR_INSUFFICIENT_BUFFER || needed == 0)
            {
                throw new Win32Exception(err);
            }
            byte[] buf = new byte[needed];
            if (!GetKernelObjectSecurity(handle, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, buf, needed, out needed))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new RawSecurityDescriptor(buf, 0);
        }

        private static void ApplyProtectedDacl(SafeFileHandle handle, IntPtr pSd)
        {
            bool present;
            bool defaulted;
            IntPtr pDacl;
            if (!GetSecurityDescriptorDacl(pSd, out present, out pDacl, out defaulted) || !present)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint rc = SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                IntPtr.Zero,
                IntPtr.Zero,
                pDacl,
                IntPtr.Zero);
            if (rc != 0)
            {
                throw new Win32Exception((int)rc);
            }
        }

        private static void AssertNoNestedReparsePoints(string dir)
        {
            string[] entries = Directory.GetFileSystemEntries(dir);
            for (int i = 0; i < entries.Length; i++)
            {
                string entry = entries[i];
                uint attrs = GetFileAttributesW(entry);
                if (attrs == INVALID_FILE_ATTRIBUTES)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    throw new UnauthorizedAccessException("Refusing to use state directory containing reparse point: " + entry);
                }
                if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    AssertNoNestedReparsePoints(entry);
                }
            }
        }

        private static void TightenChildrenDacl(string dir, IntPtr pDirSd, IntPtr pFileSd, string currentAdminSid)
        {
            string[] entries = Directory.GetFileSystemEntries(dir);
            for (int i = 0; i < entries.Length; i++)
            {
                string entry = entries[i];
                uint attrs = GetFileAttributesW(entry);
                if (attrs == INVALID_FILE_ATTRIBUTES)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    throw new UnauthorizedAccessException("Refusing to modify reparse point: " + entry);
                }
                bool isDir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
                uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (isDir ? FILE_FLAG_BACKUP_SEMANTICS : 0);
                using (SafeFileHandle child = CreateFileW(entry, READ_CONTROL | WRITE_DAC, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero))
                {
                    if (child.IsInvalid)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    BY_HANDLE_FILE_INFORMATION info;
                    if (!GetFileInformationByHandle(child, out info))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    {
                        throw new UnauthorizedAccessException("Refusing to modify reparse point: " + entry);
                    }
                    RawSecurityDescriptor rsd = ReadSecurityDescriptor(child);
                    bool trustedChildOwner = rsd.Owner != null
                        && (IsTrustedSid(rsd.Owner.Value)
                            || (currentAdminSid != null && string.Equals(rsd.Owner.Value, currentAdminSid, StringComparison.OrdinalIgnoreCase)));
                    if (!trustedChildOwner)
                    {
                        string ownerSid = rsd.Owner != null ? rsd.Owner.Value : "unknown";
                        throw new UnauthorizedAccessException("Refusing to use state item owned by untrusted account (" + ownerSid + "): " + entry);
                    }
                    ApplyProtectedDacl(child, isDir ? pDirSd : pFileSd);
                }
                if (isDir)
                {
                    TightenChildrenDacl(entry, pDirSd, pFileSd, currentAdminSid);
                }
            }
        }

        public static void EnsureSecureStateDirectory(string path)
        {
            IntPtr pDirSd = IntPtr.Zero;
            IntPtr pFileSd = IntPtr.Zero;
            uint sdSize = 0;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(StateDirSddl, SDDL_REVISION_1, out pDirSd, out sdSize))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(StateFileSddl, SDDL_REVISION_1, out pFileSd, out sdSize))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = pDirSd;
                sa.bInheritHandle = false;

                if (CreateDirectoryW(path, ref sa))
                {
                    return;
                }
                int createErr = Marshal.GetLastWin32Error();
                if (createErr != ERROR_ALREADY_EXISTS)
                {
                    throw new Win32Exception(createErr);
                }

                uint attrs = GetFileAttributesW(path);
                if (attrs == INVALID_FILE_ATTRIBUTES)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    throw new UnauthorizedAccessException("Refusing to use state path because it is a reparse point / junction: " + path);
                }
                if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    throw new UnauthorizedAccessException("Refusing to use state path because it exists and is not a directory: " + path);
                }

                using (SafeFileHandle handle = CreateFileW(
                    path,
                    READ_CONTROL | WRITE_DAC,
                    FILE_SHARE_ALL,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    IntPtr.Zero))
                {
                    if (handle.IsInvalid)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    BY_HANDLE_FILE_INFORMATION info;
                    if (!GetFileInformationByHandle(handle, out info))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        throw new UnauthorizedAccessException("Refusing to use untrusted state path: " + path);
                    }

                    RawSecurityDescriptor rsd = ReadSecurityDescriptor(handle);
                    if (rsd.Owner == null || !IsTrustedSid(rsd.Owner.Value))
                    {
                        string ownerSid = rsd.Owner != null ? rsd.Owner.Value : "unknown";
                        throw new UnauthorizedAccessException(
                            "Refusing to use existing state directory " + path + " owned by untrusted account (" + ownerSid + "). Remove it after inspection and rerun the installer.");
                    }

                    if (rsd.DiscretionaryAcl != null)
                    {
                        for (int i = 0; i < rsd.DiscretionaryAcl.Count; i++)
                        {
                            CommonAce ace = rsd.DiscretionaryAcl[i] as CommonAce;
                            if (ace != null && ace.AceType == AceType.AccessAllowed && !IsTrustedSid(ace.SecurityIdentifier.Value))
                            {
                                if ((ace.AccessMask & UntrustedWriteMask) != 0)
                                {
                                    throw new UnauthorizedAccessException(
                                        "Refusing to use existing state directory " + path + " because it grants write access to untrusted account (" + ace.SecurityIdentifier.Value + "). Remove it after inspection and rerun the installer.");
                                }
                            }
                        }
                    }

                    string currentAdminSid = null;
                    using (WindowsIdentity current = WindowsIdentity.GetCurrent())
                    {
                        if (current != null && current.User != null)
                        {
                            currentAdminSid = current.User.Value;
                        }
                    }

                    AssertNoNestedReparsePoints(path);
                    ApplyProtectedDacl(handle, pDirSd);
                    TightenChildrenDacl(path, pDirSd, pFileSd, currentAdminSid);
                }
            }
            finally
            {
                if (pFileSd != IntPtr.Zero)
                {
                    LocalFree(pFileSd);
                }
                if (pDirSd != IntPtr.Zero)
                {
                    LocalFree(pDirSd);
                }
            }
        }

        public static void RemoveStateDirectorySafely(string path)
        {
            uint attrs = GetFileAttributesW(path);
            if (attrs == INVALID_FILE_ATTRIBUTES)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                {
                    return;
                }
                throw new Win32Exception(err);
            }
            if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new UnauthorizedAccessException("Refusing to purge state path because it is a reparse point / junction: " + path);
            }
            if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                throw new UnauthorizedAccessException("Refusing to purge state path because it is not a directory: " + path);
            }
            using (SafeFileHandle handle = CreateFileW(
                path,
                READ_CONTROL,
                FILE_SHARE_ALL,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(handle, out info))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    throw new UnauthorizedAccessException("Refusing to purge untrusted state path: " + path);
                }
                RawSecurityDescriptor rsd = ReadSecurityDescriptor(handle);
                if (rsd.Owner == null || !IsTrustedSid(rsd.Owner.Value))
                {
                    string ownerSid = rsd.Owner != null ? rsd.Owner.Value : "unknown";
                    throw new UnauthorizedAccessException("Refusing to purge state directory " + path + " owned by untrusted account (" + ownerSid + ").");
                }
            }
            DeleteTreeNoFollow(path);
        }

        private static void DeleteTreeNoFollow(string dir)
        {
            string[] entries = Directory.GetFileSystemEntries(dir);
            for (int i = 0; i < entries.Length; i++)
            {
                string entry = entries[i];
                uint attrs = GetFileAttributesW(entry);
                if (attrs == INVALID_FILE_ATTRIBUTES)
                {
                    continue;
                }
                bool isDir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
                bool isReparse = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                if (isReparse)
                {
                    // Remove only the reparse point itself; never traverse into its target.
                    if (isDir)
                    {
                        if (!RemoveDirectoryW(entry))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }
                    else
                    {
                        File.Delete(entry);
                    }
                }
                else if (isDir)
                {
                    DeleteTreeNoFollow(entry);
                }
                else
                {
                    if ((attrs & FILE_ATTRIBUTE_READONLY) != 0)
                    {
                        SetFileAttributesW(entry, attrs & ~FILE_ATTRIBUTE_READONLY);
                    }
                    File.Delete(entry);
                }
            }
            uint dirAttrs = GetFileAttributesW(dir);
            if (dirAttrs != INVALID_FILE_ATTRIBUTES && (dirAttrs & FILE_ATTRIBUTE_READONLY) != 0)
            {
                SetFileAttributesW(dir, dirAttrs & ~FILE_ATTRIBUTE_READONLY);
            }
            if (!RemoveDirectoryW(dir))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        // Pure RFC 8032 Ed25519 signature verification using BigInteger + SHA512.
        private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        private static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);
        private static readonly BigInteger D = Mod(-121665 * BigInteger.ModPow(121666, P - 2, P), P);
        private static readonly BigInteger D2 = Mod(2 * D, P);
        private static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);
        private static readonly BigInteger PMinus5Div8 = (P - 5) / 8;
        private static readonly BigInteger Bx = BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202", CultureInfo.InvariantCulture);
        private static readonly BigInteger By = Mod(4 * BigInteger.ModPow(5, P - 2, P), P);
        private static readonly Point BasePoint = new Point(Bx, By, BigInteger.One, Mod(Bx * By, P));

        private sealed class Point
        {
            public readonly BigInteger X;
            public readonly BigInteger Y;
            public readonly BigInteger Z;
            public readonly BigInteger T;

            public Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t)
            {
                X = x;
                Y = y;
                Z = z;
                T = t;
            }
        }

        private static BigInteger Mod(BigInteger value, BigInteger modulus)
        {
            BigInteger r = value % modulus;
            return r.Sign < 0 ? r + modulus : r;
        }

        private static BigInteger FromUnsignedLE(byte[] src, int offset, int count)
        {
            byte[] tmp = new byte[count + 1];
            Buffer.BlockCopy(src, offset, tmp, 0, count);
            return new BigInteger(tmp);
        }

        private static byte[] DecodeBase64UrlExact(string text, int expectedChars, int expectedBytes)
        {
            if (text == null)
            {
                return null;
            }
            text = text.Trim();
            if (text.Length != expectedChars)
            {
                return null;
            }
            char[] std = new char[expectedChars + ((4 - (expectedChars % 4)) % 4)];
            for (int i = 0; i < expectedChars; i++)
            {
                char c = text[i];
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
                {
                    std[i] = c;
                }
                else if (c == '-')
                {
                    std[i] = '+';
                }
                else if (c == '_')
                {
                    std[i] = '/';
                }
                else
                {
                    return null;
                }
            }
            for (int i = expectedChars; i < std.Length; i++)
            {
                std[i] = '=';
            }
            try
            {
                byte[] decoded = Convert.FromBase64String(new string(std));
                return decoded.Length == expectedBytes ? decoded : null;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        private static Point DecodePoint(byte[] buf, int offset)
        {
            int sign = (buf[offset + 31] >> 7) & 1;
            byte[] yBytes = new byte[33];
            Buffer.BlockCopy(buf, offset, yBytes, 0, 32);
            yBytes[31] &= 0x7F;
            BigInteger y = new BigInteger(yBytes);
            if (y >= P)
            {
                return null;
            }
            BigInteger y2 = Mod(y * y, P);
            BigInteger u = Mod(y2 - BigInteger.One, P);
            BigInteger v = Mod(D * y2 + BigInteger.One, P);
            BigInteger v3 = BigInteger.ModPow(v, 3, P);
            BigInteger v7 = Mod(Mod(v3 * v3, P) * v, P);
            BigInteger x = Mod(Mod(u * v3, P) * BigInteger.ModPow(Mod(u * v7, P), PMinus5Div8, P), P);
            BigInteger vx2 = Mod(v * Mod(x * x, P), P);
            if (vx2 == Mod(-u, P))
            {
                x = Mod(x * I, P);
            }
            else if (vx2 != u)
            {
                return null;
            }
            if (x.IsZero && sign == 1)
            {
                return null;
            }
            int xSign = x.IsEven ? 0 : 1;
            if (xSign != sign)
            {
                x = P - x;
            }
            return new Point(x, y, BigInteger.One, Mod(x * y, P));
        }

        private static Point PointAdd(Point p1, Point p2)
        {
            BigInteger a = Mod((p1.Y - p1.X) * (p2.Y - p2.X), P);
            BigInteger b = Mod((p1.Y + p1.X) * (p2.Y + p2.X), P);
            BigInteger c = Mod(Mod(p1.T * D2, P) * p2.T, P);
            BigInteger d = Mod(p1.Z * 2 * p2.Z, P);
            BigInteger e = Mod(b - a, P);
            BigInteger f = Mod(d - c, P);
            BigInteger g = Mod(d + c, P);
            BigInteger h = Mod(b + a, P);
            return new Point(Mod(e * f, P), Mod(g * h, P), Mod(f * g, P), Mod(e * h, P));
        }

        private static Point ScalarMult(Point pt, BigInteger s)
        {
            Point res = new Point(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
            Point addend = pt;
            while (s.Sign > 0)
            {
                if (!s.IsEven)
                {
                    res = PointAdd(res, addend);
                }
                addend = PointAdd(addend, addend);
                s >>= 1;
            }
            return res;
        }

        public static bool VerifyManifest(byte[] manifestBytes, string signatureB64Url, string publicKeyB64Url)
        {
            if (manifestBytes == null)
            {
                return false;
            }
            byte[] pub = DecodeBase64UrlExact(publicKeyB64Url, 43, 32);
            byte[] sig = DecodeBase64UrlExact(signatureB64Url, 86, 64);
            if (pub == null || sig == null)
            {
                return false;
            }
            BigInteger s = FromUnsignedLE(sig, 32, 32);
            if (s >= L)
            {
                return false;
            }
            Point a = DecodePoint(pub, 0);
            Point r = DecodePoint(sig, 0);
            if (a == null || r == null)
            {
                return false;
            }

            byte[] prefix = Encoding.ASCII.GetBytes("i3t-signature-v1");
            byte[] purpose = Encoding.ASCII.GetBytes("release-manifest");
            byte[] hashInput = new byte[32 + 32 + prefix.Length + 1 + purpose.Length + manifestBytes.Length];
            int pos = 0;
            Buffer.BlockCopy(sig, 0, hashInput, pos, 32);
            pos += 32;
            Buffer.BlockCopy(pub, 0, hashInput, pos, 32);
            pos += 32;
            Buffer.BlockCopy(prefix, 0, hashInput, pos, prefix.Length);
            pos += prefix.Length;
            hashInput[pos++] = (byte)purpose.Length;
            Buffer.BlockCopy(purpose, 0, hashInput, pos, purpose.Length);
            pos += purpose.Length;
            Buffer.BlockCopy(manifestBytes, 0, hashInput, pos, manifestBytes.Length);

            byte[] digest;
            using (SHA512 sha = SHA512.Create())
            {
                digest = sha.ComputeHash(hashInput);
            }
            BigInteger k = Mod(FromUnsignedLE(digest, 0, 64), L);
            Point lhs = ScalarMult(BasePoint, s);
            Point rhs = PointAdd(r, ScalarMult(a, k));
            return Mod(lhs.X * rhs.Z - rhs.X * lhs.Z, P).IsZero
                && Mod(lhs.Y * rhs.Z - rhs.Y * lhs.Z, P).IsZero;
        }
    }
}
'@
        Add-Type -TypeDefinition $nativeSource -ReferencedAssemblies 'System.Numerics' -ErrorAction Stop
    }

    # Downloads over HTTPS only, refusing non-HTTPS URLs and HTTPS->HTTP redirects, with strict timeout and size cap.
    function Invoke-HttpsDownload([string]$Url, [string]$DestinationPath, [long]$MaxBytes, [int]$TimeoutSec = 120) {
        $currentUri = $null
        if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$currentUri) -or ($currentUri.Scheme -cne 'https')) {
            throw "Release URL must use https:// (got: $Url)"
        }
        $maxRedirects = 10
        for ($hop = 0; $hop -le $maxRedirects; $hop++) {
            $request = [Net.HttpWebRequest]::Create($currentUri)
            $request.Method = 'GET'
            $request.AllowAutoRedirect = $false
            $request.Timeout = $TimeoutSec * 1000
            $request.ReadWriteTimeout = $TimeoutSec * 1000
            $request.UserAgent = 'ice3tier-installer'
            $response = $null
            try {
                try {
                    $response = [Net.HttpWebResponse]$request.GetResponse()
                } catch [Net.WebException] {
                    if ($null -ne $_.Exception.Response) {
                        $response = [Net.HttpWebResponse]$_.Exception.Response
                    } else {
                        throw
                    }
                }
                $code = [int]$response.StatusCode
                if ($code -in 301, 302, 303, 307, 308) {
                    $location = $response.Headers['Location']
                    if (-not $location) { throw "Redirect response from $currentUri lacked Location header" }
                    $nextUri = New-Object Uri($currentUri, $location)
                    if ($nextUri.Scheme -cne 'https') {
                        throw "Refusing insecure redirect from $currentUri to $nextUri"
                    }
                    $currentUri = $nextUri
                    continue
                }
                if ($code -ne 200) {
                    throw "Failed to download ${currentUri}: HTTP $code"
                }
                if (($response.ContentLength -gt 0) -and ($response.ContentLength -gt $MaxBytes)) {
                    throw "Download from $currentUri exceeds size limit ($($response.ContentLength) > $MaxBytes bytes)"
                }
                $inStream = $response.GetResponseStream()
                $outStream = [IO.File]::Open($DestinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $buffer = New-Object byte[] 65536
                    [long]$total = 0
                    while (($read = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $total += $read
                        if ($total -gt $MaxBytes) {
                            throw "Download from $currentUri exceeded size limit ($MaxBytes bytes)"
                        }
                        $outStream.Write($buffer, 0, $read)
                    }
                } finally {
                    $outStream.Dispose()
                    $inStream.Dispose()
                }
                return
            } finally {
                if ($null -ne $response) { $response.Dispose() }
            }
        }
        throw "Too many redirects downloading $Url"
    }

    # Safely extracts a verified ZIP archive using an exact filename allowlist (no subdirectories, no Zip Slip).
    function Expand-VerifiedZip([string]$ZipPath, [string]$DestinationDir, [string[]]$AllowList) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $destFull = [IO.Path]::GetFullPath($DestinationDir)
        if (-not $destFull.EndsWith([IO.Path]::DirectorySeparatorChar)) {
            $destFull += [IO.Path]::DirectorySeparatorChar
        }
        [long]$maxTotalBytes = 256MB
        [long]$totalExtracted = 0
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
        try {
            foreach ($entry in $archive.Entries) {
                $entryName = $entry.FullName
                if ([string]::IsNullOrEmpty($entryName) -or ($entryName -match '[/\\:]') -or ($entryName.Contains('..'))) {
                    throw "Refusing unsafe ZIP entry path: $entryName"
                }
                $canonical = $AllowList | Where-Object { $_ -ieq $entryName } | Select-Object -First 1
                if (-not $canonical) {
                    throw "Refusing unexpected file in archive: $entryName"
                }
                if (-not $seen.Add($canonical)) {
                    throw "Refusing duplicate file in archive: $entryName"
                }
                if (($entry.Length -lt 0) -or ($entry.Length -gt $maxTotalBytes)) {
                    throw "ZIP entry $entryName exceeds allowed uncompressed size"
                }
                $targetPath = [IO.Path]::GetFullPath((Join-Path $DestinationDir $canonical))
                if (-not $targetPath.StartsWith($destFull, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Refusing ZIP entry escaping destination: $entryName"
                }
                $inStream = $entry.Open()
                $outStream = [IO.File]::Open($targetPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $buffer = New-Object byte[] 65536
                    while (($read = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $totalExtracted += $read
                        if ($totalExtracted -gt $maxTotalBytes) {
                            throw "Archive uncompressed size exceeded limit ($maxTotalBytes bytes)"
                        }
                        $outStream.Write($buffer, 0, $read)
                    }
                } finally {
                    $outStream.Dispose()
                    $inStream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    }

    function Resolve-ManifestAsset($ManifestObj, [string]$AssetName) {
        foreach ($sectionName in 'artifacts', 'files') {
            $sectionProp = $ManifestObj.PSObject.Properties[$sectionName]
            if ($null -eq $sectionProp -or $null -eq $sectionProp.Value) { continue }
            foreach ($entryProp in $sectionProp.Value.PSObject.Properties) {
                $item = $entryProp.Value
                if (($null -ne $item) -and ($item.file -ceq $AssetName)) {
                    if (($sectionName -eq 'files') -and ($entryProp.Name -cne $AssetName)) { continue }
                    return $item
                }
            }
        }
        return $null
    }

    # Puts the install directory on the machine PATH, or takes it off. The value is read and written as it is stored
    # (entries such as %SystemRoot%\system32 stay unexpanded), which [Environment]::SetEnvironmentVariable would not do.
    function Set-MachinePath([bool]$present) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
        try {
            $current = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $entries = @($current -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $dir) })
            if ($present) { $entries += $dir }
            $wanted = $entries -join ';'
            if ($wanted -eq $current.TrimEnd(';')) { return }
            $key.SetValue('Path', $wanted, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        } finally {
            $key.Close()
        }
        # Programs that are already running (Explorer, and so every terminal opened from now on) only reread the
        # environment when told to; setting any machine variable sends that notice.
        [Environment]::SetEnvironmentVariable('I3T_PATH_CHANGED', '1', 'Machine')
        [Environment]::SetEnvironmentVariable('I3T_PATH_CHANGED', $null, 'Machine')
    }

    # Runs an action on files that a process which has just stopped may still hold open for a moment.
    function Invoke-Released([scriptblock]$action) {
        for ($attempt = 1; ; $attempt++) {
            try {
                & $action
                return
            } catch {
                if ($attempt -ge 20) { throw }
                Start-Sleep -Milliseconds 500
            }
        }
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required: open PowerShell with "Run as administrator" and run this again.'
    }

    if ($removing) {
        if (Test-Path -LiteralPath $exe) {
            Say "Removing the $service service"
            & $exe service uninstall
            if ($LASTEXITCODE -ne 0) { throw 'i3t service uninstall failed' }
            # Firewall rules a node that was killed may have left behind. Nothing to do is fine too.
            & $exe network cleanup | Out-Null
        } elseif (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            # The program is gone but its service is still registered.
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            & sc.exe delete $service | Out-Null
        }
        Set-MachinePath $false
        if (Test-Path -LiteralPath $dir) {
            Say "Removing $dir"
            Invoke-Released { Remove-Item -LiteralPath $dir -Recurse -Force }
        }
        if ($purging) {
            Say "Removing $state"
            [Ice3tier.Installer.Native]::RemoveStateDirectorySafely($state)
        }
        Say 'Uninstalled'
        return
    }
    if ($purging) {
        throw 'I3T_PURGE can only be used with I3T_UNINSTALL'
    }

    if (($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') -and ($env:PROCESSOR_ARCHITEW6432 -ne 'AMD64')) {
        throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE (only x86_64 is supported)"
    }

    if ($version) {
        if ($version -notmatch '^v') { $version = "v$version" }
        if (($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$') -or $version.Contains('..')) {
            throw "Invalid I3T_VERSION value: $version"
        }
    }
    if ($releaseKey -and ($releaseKey -notmatch '^[0-9A-Za-z_-]{43}$')) {
        throw 'Invalid I3T_RELEASE_KEY value (must be 43-character base64url)'
    }

    $work = Join-Path ([IO.Path]::GetTempPath()) ('i3t-install-' + [Guid]::NewGuid().ToString('N'))
    [Ice3tier.Installer.Native]::EnsureSecureStateDirectory($work)
    $prevSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        if ($from) {
            foreach ($name in 'i3t.exe', 'wintun.dll') {
                $source = Join-Path $from $name
                if (-not (Test-Path -LiteralPath $source)) { throw "$name not found in $from" }
                Copy-Item -LiteralPath $source -Destination (Join-Path $work $name)
            }
            $license = Join-Path $from 'wintun-LICENSE.txt'
            if (Test-Path -LiteralPath $license) { Copy-Item -LiteralPath $license -Destination (Join-Path $work 'wintun-LICENSE.txt') }
        } else {
            if (-not $releaseBase) { $releaseBase = 'https://github.com/fuqiuluo/ice3tier/releases' }
            $releaseBase = $releaseBase.TrimEnd('/')
            if (($releaseBase -notmatch '^https://\S+$')) {
                throw "I3T_RELEASE_BASE must use https:// (got: $releaseBase)"
            }

            # Restrict TLS to 1.2+ (do not keep legacy SSL3/TLS 1.0/1.1 enabled).
            $tls = [Net.SecurityProtocolType]::Tls12
            if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
                $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
            }
            [Net.ServicePointManager]::SecurityProtocol = $tls

            $manifestPrefix = if ($version) { "$releaseBase/download/$version" } else { "$releaseBase/latest/download" }
            $manifestPath = Join-Path $work 'manifest.json'
            $sigPath = Join-Path $work 'manifest.json.sig'
            Say 'Downloading and verifying release manifest'
            Invoke-HttpsDownload -Url "$manifestPrefix/manifest.json" -DestinationPath $manifestPath -MaxBytes 1MB -TimeoutSec 30
            Invoke-HttpsDownload -Url "$manifestPrefix/manifest.json.sig" -DestinationPath $sigPath -MaxBytes 4KB -TimeoutSec 30

            $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
            $sigText = [IO.File]::ReadAllText($sigPath, [Text.Encoding]::ASCII).Trim()
            $verified = [Ice3tier.Installer.Native]::VerifyManifest($manifestBytes, $sigText, $releasePublicKey)
            if ((-not $verified) -and $releaseKey) {
                $verified = [Ice3tier.Installer.Native]::VerifyManifest($manifestBytes, $sigText, $releaseKey)
            }
            if (-not $verified) {
                throw 'Release manifest signature verification failed'
            }

            $manifestObj = ([Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json)
            $manifestVersion = [string]$manifestObj.version
            if ((-not $manifestVersion) -or ($manifestVersion -notmatch '^[0-9A-Za-z.-]+$') -or $manifestVersion.Contains('..')) {
                throw "Invalid version in signed manifest: $manifestVersion"
            }
            if ($version -and ($manifestVersion -cne $version.Substring(1))) {
                throw "Manifest version mismatch: expected $($version.Substring(1)), got $manifestVersion"
            }

            $entry = Resolve-ManifestAsset -ManifestObj $manifestObj -AssetName $asset
            if ($null -eq $entry) {
                throw "$asset is not covered by the signed manifest"
            }
            $expectedSize = [long]$entry.size
            $expectedSha256 = ([string]$entry.sha256).ToLowerInvariant()
            if (($expectedSize -le 0) -or ($expectedSha256 -notmatch '^[0-9a-f]{64}$')) {
                throw "Malformed manifest entry for $asset"
            }

            $url = "$releaseBase/download/v$manifestVersion/$asset"
            Say "Downloading $url"
            $zip = Join-Path $work $asset
            Invoke-HttpsDownload -Url $url -DestinationPath $zip -MaxBytes $expectedSize -TimeoutSec 300

            $actualSize = (Get-Item -LiteralPath $zip).Length
            if ($actualSize -ne $expectedSize) {
                throw "Size mismatch for ${asset}: expected $expectedSize bytes, got $actualSize"
            }
            $actualSha256 = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualSha256 -cne $expectedSha256) {
                throw "SHA-256 mismatch for ${asset}: expected $expectedSha256, got $actualSha256"
            }
            Say "Verified $asset (SHA-256 matches signed manifest)"

            Expand-VerifiedZip -ZipPath $zip -DestinationDir $work -AllowList $allowedFiles
            Remove-Item -LiteralPath $zip
            foreach ($name in 'i3t.exe', 'wintun.dll') {
                if (-not (Test-Path -LiteralPath (Join-Path $work $name))) { throw "$name is missing from $asset" }
            }
        }

        # Validate or atomically create %ProgramData%\i3t BEFORE touching Program Files or the service,
        # rejecting reparse points / NTFS junctions and untrusted owners/write ACEs fail-closed.
        [Ice3tier.Installer.Native]::EnsureSecureStateDirectory($state)

        $registered = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($registered -and ($registered.Status -ne 'Stopped')) {
            Say "Stopping the $service service"
            Stop-Service -Name $service -Force
        }

        Say "Installing i3t to $dir"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        foreach ($name in $allowedFiles) {
            $src = Join-Path $work $name
            if (Test-Path -LiteralPath $src) {
                Invoke-Released { Copy-Item -LiteralPath $src -Destination (Join-Path $dir $name) -Force }
            }
        }

        Say "Registering the $service service (starts at boot)"
        & $exe service install
        if ($LASTEXITCODE -ne 0) { throw 'i3t service install failed' }

        Set-MachinePath $true
        # This window too, so that `i3t` works in it right away.
        if (@($env:Path -split ';') -notcontains $dir) { $env:Path = $env:Path.TrimEnd(';') + ';' + $dir }

        if ($token) {
            Say 'Joining the network'
            $arguments = @('join')
            if ($relay) { $arguments += '--can-relay' }
            if ($canExit) { $arguments += '--can-exit' }
            # `i3t join` starts the service once the node has joined.
            $token | & $exe @arguments
            if ($LASTEXITCODE -ne 0) { throw 'i3t join failed' }
            Say 'i3t is running (check with: i3t status)'
        } elseif (Test-Path -LiteralPath (Join-Path $state 'controller.json')) {
            Say "This node has already joined; starting the $service service"
            Start-Service -Name $service
            Say 'i3t upgraded and running (check with: i3t status)'
        } else {
            Say 'Installation complete!'
            Write-Host ''
            Write-Host 'Next step (joins and starts the service):'
            Write-Host '  echo <enrollment-token> | i3t join   # add --can-relay or --can-exit if needed'
        }
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $prevSecurityProtocol
        if (Test-Path -LiteralPath $work) {
            try { [Ice3tier.Installer.Native]::RemoveStateDirectorySafely($work) } catch { }
        }
    }
}

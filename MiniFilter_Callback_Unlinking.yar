rule MiniFilter_Callback_Unlinking
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects MiniFilter Callback Unlinking technique — usermode tooling that walks FltMgr internal structures and delinks callback nodes from volume operation lists to silence EDR file telemetry. Not tied to a specific implementation."
        severity    = "critical"
        category    = "defense-evasion"
        technique   = "MiniFilter Callback Unlinking"

    strings:
        // FltMgr exports commonly resolved to locate FltGlobals or enumerate filters
        $flt_export_1 = "FltEnumerateFilters"       ascii wide
        $flt_export_2 = "FltGetFilterInformation"   ascii wide
        $flt_export_3 = "FltEnumerateInstances"     ascii wide

        // fltmgr.sys loaded as a data file for pattern scanning
        $fltmgr_str_1 = "fltmgr.sys"               ascii wide nocase
        $fltmgr_str_2 = "\\fltmgr"                 ascii wide nocase

        // Vulnerable drivers commonly used for kernel R/W primitives (BYOVD)
        $byovd_1 = "RTCore64"                       ascii wide
        $byovd_2 = "\\.\GIO"                        ascii wide
        $byovd_3 = "dbutil_2_3"                     ascii wide
        $byovd_4 = "WinRing0"                       ascii wide
        $byovd_5 = "PROCEXP152"                     ascii wide

        // Device names commonly targeted — these are the volumes FltMgr attaches to
        $vol_1 = "\\Device\\HarddiskVolume"         ascii wide
        $vol_2 = "\\Device\\Mup"                    ascii wide

        // NtQuerySystemInformation class 11 = SystemModuleInformation
        // Used to enumerate kernel modules and find fltmgr base
        $nt_sysmod = "NtQuerySystemInformation"     ascii wide

        // Known FltMgr internal structure field names that appear in debug builds
        // or strings left in tooling source / PDB references
        $struct_1 = "FltGlobals"                    ascii wide
        $struct_2 = "_FLTP_FRAME"                   ascii wide
        $struct_3 = "_CALLBACK_NODE"                ascii wide
        $struct_4 = "_FLT_VOLUME"                   ascii wide
        $struct_5 = "RegisteredFilters"             ascii wide
        $struct_6 = "AttachedVolumes"               ascii wide
        $struct_7 = "OperationLists"                ascii wide

        // Byte pattern: lea rcx, [rip + offset] used in FltEnumerateFilters
        // to reference FltGlobals+0x58 — used by tools that pattern-scan fltmgr.sys
        // in usermode to resolve FltGlobals address
        // 48 8d 0d ?? ?? ?? ?? = lea rcx, [rip+?]
        $fltglobals_scan = { 48 8D 0D ?? ?? ?? ?? }

        // IOCTL for RTCore64 kernel R/W primitive
        // 0xC3502808 encoded as little-endian DWORD
        $ioctl_rtcore = { 08 28 50 C3 }

        // Generic doubly-linked list removal pattern in x64:
        // mov [rcx], rax  (Blink->Flink = Flink)
        // mov [rax+8], rcx (Flink->Blink = Blink)
        // Commonly emitted by compilers for LIST_ENTRY removal
        $list_delink = { 48 89 01 48 89 48 08 }

        // DeviceIoControl call pattern — used to communicate with vulnerable driver
        $devioctl = "DeviceIoControl"               ascii wide

        // LoadLibraryEx with LOAD_LIBRARY_AS_DATAFILE (0x2) flag
        // used to load fltmgr.sys into usermode for pattern scanning
        $loadlib_datafile = "LoadLibraryExW"        ascii wide

    condition:
        uint16(0) == 0x5A4D  // valid PE

        and filesize < 5MB

        and (
            // Strong signal: BYOVD driver reference + FltMgr export + module enumeration
            (
                1 of ($byovd_*)
                and 1 of ($flt_export_*)
                and $nt_sysmod
            )
            or
            // Strong signal: FltGlobals pattern scan + structure references
            (
                $fltglobals_scan
                and $loadlib_datafile
                and 1 of ($fltmgr_str_*)
                and 1 of ($struct_*)
            )
            or
            // Medium signal: BYOVD + list delink pattern + volume names
            (
                1 of ($byovd_*)
                and $list_delink
                and 1 of ($vol_*)
                and $devioctl
            )
            or
            // Medium signal: multiple FltMgr internal structure references
            // — indicates tooling built around manual structure walking
            (
                3 of ($struct_*)
                and 1 of ($fltmgr_str_*)
                and $nt_sysmod
            )
        )
}

rule FileHandleRedirect_CredDump
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects binaries implementing File handle redirect for credential access"
        reference   = "https://0x12darkdev.net"
        severity    = "critical"

    strings:
        // Handle table navigation constants
        $tableCode_mask = { 48 83 E? F8 }           // tableCode & ~0x3
        $entry_calc     = { C1 E? 02 6B ?? 10 }      // (handle/4)*16

        // _FILE_OBJECT.FileName offsets
        $fname_off1 = { 66 8B 4? 58 }               // mov cx, [rX+0x58] (Length)
        $fname_off2 = { 48 8B 4? 60 }               // mov rcx, [rX+0x60] (Buffer)

        // NtQuerySystemInformation class 0x10
        $sysinfo = { B9 10 00 00 00 }

        // SAM/SYSTEM hive paths
        $sam    = "\\config\\SAM"    ascii wide nocase
        $system = "\\config\\SYSTEM" ascii wide nocase

        // OVERLAPPED I/O pattern
        $overlapped = "ReadFile" ascii

    condition:
        uint16(0) == 0x5A4D and
        $sysinfo and
        ($sam or $system) and
        $overlapped and
        (2 of ($tableCode_mask, $entry_calc, $fname_off1, $fname_off2))
}

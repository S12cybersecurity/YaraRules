rule BYOVD_DKOM_PEB_Corruption {
    meta:
        author      = "0x12 Dark Development"
        description = "Detects DKOM-based process termination via PEB pointer overwrite in EPROCESS"
        reference   = "https://0x12darkdev.net"
        technique   = "T1055 / T1014 — DKOM process object manipulation"
        severity    = "CRITICAL"
        date        = "2025"

    strings:
        // PEB-related kernel field references
        $peb1 = "Peb"            ascii
        $peb2 = "_PEB"           ascii
        $peb3 = "PEB"            ascii

        // EPROCESS and KPROCESS struct names (PDB resolution)
        $struct1 = "_EPROCESS"   ascii
        $struct2 = "_KPROCESS"   ascii

        // DirectoryTableBase — only needed if doing physical translation
        $dtb = "DirectoryTableBase" ascii

        // GIO driver device names
        $gio1 = "\\\\.\\GIO"    ascii wide
        $gio2 = "\\\\.\\GIOV3"  ascii wide

        // Kernel memcpy IOCTL
        $ioctl = { 08 28 50 C3 }

        // Standard termination APIs — expected to be ABSENT in this technique
        $t1 = "TerminateProcess"     ascii
        $t2 = "NtTerminateProcess"   ascii
        $t3 = "OpenProcess"          ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (any of ($gio*) or $ioctl) and
            any of ($peb*) and
            any of ($struct*) and
            not any of ($t*)
        )
}

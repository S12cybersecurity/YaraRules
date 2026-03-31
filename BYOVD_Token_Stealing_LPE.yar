rule BYOVD_Token_Stealing_LPE {
    meta:
        description = "Detects tools performing BYOVD Local Privilege Escalation by stealing the SYSTEM process token"
        author = "0x12 Dark Development"
        technique = "Token Stealing via Kernel R/W Primitives"
        threat_level = "Critical"
        date = "2026-03-31"

    strings:
        // Key Windows API functions used for setup and driver communication
        $api1 = "OpenProcessToken" ascii wide
        $api2 = "AdjustTokenPrivileges" ascii wide
        $api3 = "DeviceIoControl" ascii wide
        $api4 = "NtQuerySystemInformation" ascii wide
        $api5 = "LookupPrivilegeValue" ascii wide

        // Specific Privilege required for many LPE methods
        $priv = "SeDebugPrivilege" ascii wide

        // Kernel-related strings for finding the base address
        $nt1 = "ntoskrnl.exe" ascii wide nocase
        $nt2 = "ntkrnl" ascii wide nocase

        // Indicators of EPROCESS structure traversal and token manipulation
        $field1 = "PsInitialSystemProcess" ascii wide
        $field2 = "ActiveProcessLinks" ascii wide
        $field3 = "UniqueProcessId" ascii wide
        $field4 = "Token" ascii wide

        // Common driver communication patterns (Generic Device paths)
        $dev = "\\\\.\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE File
        $priv and
        (3 of ($api*)) and
        (any of ($nt*)) and
        (2 of ($field*)) and
        $dev
}

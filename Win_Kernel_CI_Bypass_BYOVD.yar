rule Win_Kernel_CI_Bypass_BYOVD {
    meta:
        description = "Detects tools that attempt to bypass Windows Code Integrity (DSE) by patching g_CiOptions using BYOVD techniques"
        author = "0x12 Dark Development"
        date = "2026-03-26"
        technique = "BYOVD - Driver Signature Enforcement Bypass"
        reference = "https://medium.com/@0x12darkdev"
        severity = "High"

    strings:
        // Privilege escalation indicators
        $s1 = "SeDebugPrivilege" ascii wide
        $s2 = "AdjustTokenPrivileges" ascii wide
        
        // Kernel module enumeration
        $s3 = "NtQuerySystemInformation" ascii wide
        $s4 = "EnumDeviceDrivers" ascii wide
        
        // Target Identification
        $t1 = "ci.dll" ascii wide nocase
        $t2 = "g_CiOptions" ascii wide
        
        // Driver Communication (Generic)
        $d1 = "\\\\.\\" ascii wide
        $d2 = "DeviceIoControl" ascii wide

        // Hex patterns for g_CiOptions bitmask manipulation (0x0 to 0xF)
        $hex_bitmask = { C6 [0-3] 0F } // mov byte ptr [reg], 0x0F (Disabling all)

    condition:
        uint16(0) == 0x5A4D and 
        (
            (all of ($s*)) and 
            (any of ($t*)) and 
            (any of ($d*))
        ) or ($hex_bitmask)
}

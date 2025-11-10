rule Donut_Process_Migration {
    meta:
        author = "0x12 Dark Development"
        description = "Detects Donut shellcode with process migration techniques"
        date = "2024-01-15"
        version = "1.1"
        reference = "Donut + Section Injection"
        severity = "High"

    strings:
        // Donut shellcode indicators
        $d1 = "donut" ascii
        $d2 = "Donut" ascii
        $d3 = "DONUT" ascii
        
        // Process injection pattern
        $d4 = "NtCreateSection" ascii wide
        $d5 = "NtMapViewOfSection" ascii wide
        $d6 = "RtlCreateUserThread" ascii wide
        $d7 = "OpenProcess" ascii wide
        
        // Shellcode constants
        $d8 = "shellcode" ascii
        $d9 = "payload" ascii
        $d10 = "encrypted" ascii
        $d11 = "decrypted" ascii
        
        // Memory protection
        $d12 = "PAGE_EXECUTE_READ" ascii
        $d13 = "SECTION_MAP_EXECUTE" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // Donut with injection APIs
            (
                (1 of ($d1, $d2, $d3)) and
                (1 of ($d4, $d5, $d6, $d7))
            ) or
            // Injection pattern with shellcode handling
            (
                (2 of ($d4, $d5, $d6, $d7)) and
                (2 of ($d8, $d9, $d10, $d11)) and
                (1 of ($d12, $d13))
            )
        )
}

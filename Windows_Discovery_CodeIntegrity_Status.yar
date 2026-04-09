rule Windows_Discovery_CodeIntegrity_Status {
    meta:
        author = "0x12 Dark Development"
        description = "Detects binaries querying Windows Code Integrity (CI) status via NtQuerySystemInformation (Class 103)"
        technique = "Discovery - Code Integrity Status"
        reference = "https://medium.com/@0x12darkdev/discover-code-integrity-protection-status-f7c87c0a9b8e"
        date = "2026-04-09"

    strings:
        // The API used to query system information
        $api = "NtQuerySystemInformation" ascii wide

        // Specific bitmask flag names often found in PoCs or tools using this logic
        $f1 = "CODEINTEGRITY_OPTION_ENABLED" ascii wide
        $f2 = "CODEINTEGRITY_OPTION_TESTSIGN" ascii wide
        $f3 = "CODEINTEGRITY_OPTION_UMCI_ENABLED" ascii wide
        $f4 = "CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED" ascii wide
        $f5 = "CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED" ascii wide

        /* Hex Pattern for SystemCodeIntegrityInformation (Value 103 / 0x67) 
           This value is passed as the first argument to NtQuerySystemInformation.
        */
        // x64: mov rcx, 0x67
        $class_x64 = { 48 C7 C1 67 00 00 00 }
        
        // x86: push 0x67
        $class_x86 = { 6A 67 }

    condition:
        uint16(0) == 0x5A4D and // Check for MZ header (PE file)
        (
            ($api and 1 of ($f*)) or // API combined with interpretation strings
            ($api and (1 of ($class*))) // API combined with the specific Enum value
        )
}

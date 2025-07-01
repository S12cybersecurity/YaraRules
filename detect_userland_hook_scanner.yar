rule Detect_Userland_Hook_Scanner
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects C++ code that scans for JMP instructions in Nt* functions to identify userland hooks"
        version = "1.0"
        date = "2025-07-01"
        malware_family = "UserlandHookScanner"
        category = "RedTeamTools / Malware Research"
    
    strings:
        $s1 = "ntdll.dll" ascii
        $s2 = "Nt" ascii
        $s3 = { 74 02 80 3C 17 FF } // Typical pattern: cmp/jmp for FF 25
        $s4 = { 80 3C 17 E9 }       // cmp [rdi], 0xE9
        $s5 = "IsJmpInstruction" ascii
        $s6 = "ImageDirectoryEntryToData" ascii
        $s7 = "AddressOfFunctions" ascii
        $s8 = "AddressOfNames" ascii
        $s9 = "AddressOfNameOrdinals" ascii
        $sa = "strncmp" ascii

    condition:
        all of ($s1, $s2, $s5, $s6, $s7, $s8, $s9) and 2 of ($s3, $s4, $sa)
}

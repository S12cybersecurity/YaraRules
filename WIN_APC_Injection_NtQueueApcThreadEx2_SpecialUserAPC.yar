rule WIN_APC_Injection_NtQueueApcThreadEx2_SpecialUserAPC_0x12DarkDev
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects modern APC process injection using NtQueueApcThreadEx2 with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC (0x2) - Tartarus Gate technique"
        date        = "2025-12-09"
        version     = "2.1"
        mitre       = "T1055.004"
        confidence  = "High"
        category    = "Process Injection"
        reference   = "https://medium.com/@0x12darkdev"

    strings:
        // NtQueueApcThreadEx2 function name (common in unpacked samples)
        $api1 = "NtQueueApcThreadEx2" ascii wide

        // Special User APC flag: 0x2 (most common)
        $flag1 = { 02 00 00 00 } // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC

        // KERNEL_USER_APC struct pattern (Windows 11 23H2+ style)
        // ApcRoutine = remote shellcode addr, Args = NULLs
        $struct1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

        // Old style: direct shellcode pointer as 4th arg
        $old_call = { 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 41 B8 02 00 00 00 } // call NtQueueApcThreadEx2 with 0x2

        // VirtualAllocEx + PAGE_EXECUTE_READWRITE (0x40) pattern
        $rwx1 = { 40 00 00 00 } // MEM_COMMIT | PAGE_EXECUTE_READWRITE

        // Common APC queue sequence: OpenThread + VirtualAllocEx + WriteProcessMemory + NtQueueApcThreadEx2
        $seq1 = "OpenThread" ascii wide
        $seq2 = "VirtualAllocEx" ascii wide
        $seq3 = "WriteProcessMemory" ascii wide

        // Speck encryption artifacts (optional bonus for your style)
        $speck1 = "speck_decrypt" ascii wide nocase
        $speck2 = "decryptShellcode" ascii wide
        $speck3 = { 48 8D 0D ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 89 } // typical Speck decrypt call pattern

    condition:
        // Must have the API name OR strong behavioral pattern
        $api1 or

        // Special User APC flag + RWX allocation
        ( $flag1 and $rwx1 ) or

        // KERNEL_USER_APC struct (24 NULL bytes = 3x PVOIDs) near flag
        ( $flag1 and $struct1 within 100 ) or

        // Classic call sequence with 0x2 flag
        ( $old_call and $flag1 ) or

        // Full behavioral chain
        ( 2 of ($seq*) and $rwx1 and $flag1 ) or

        // Bonus: Speck + Special APC (your exact combo)
        ( any of ($speck*) and $flag1 )

        // File size filter to reduce FP on clean ntdll.dll
        and filesize < 15MB
}

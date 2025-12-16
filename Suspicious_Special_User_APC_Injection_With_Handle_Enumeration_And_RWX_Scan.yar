rule Suspicious_Special_User_APC_Injection_With_Handle_Enumeration_And_RWX_Scan
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects binaries that combine system-wide handle enumeration (likely for leaked/open handles), RWX memory region scanning in remote processes, and use of NtQueueApcThreadEx2 with the special user APC flag for forced execution. Characteristic of advanced stealthy APC-based process injection techniques (e.g., Frankenstein APC Injection variants)."
        date = "2025-12-16"
        category = "Process Injection"
        technique = "T1055.004 - Asynchronous Procedure Call (Special User APC)"
        confidence = "Medium-High"
        reference = "Advanced evasion using existing handles, natural RWX regions, and QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC"

    strings:
        // NtQuerySystemInformation with SystemHandleInformation (5) or SystemExtendedHandleInformation (64) - common for handle leaking/enumeration
        $handle_enum1 = { 68 05 00 00 00 }                   // push 5 ; SystemHandleInformation
        $handle_enum2 = { 68 40 00 00 00 }                   // push 64 ; SystemExtendedHandleInformation
        $ntqsi = "NtQuerySystemInformation" ascii wide

        // VirtualQueryEx loop for finding RWX (PAGE_EXECUTE_READWRITE = 0x40)
        $vqe = "VirtualQueryEx" ascii wide
        $protect_rwx = { 83 ?? 40 }                          // cmp dword, 0x40 (PAGE_EXECUTE_READWRITE)
        $hex_rwx = { C7 ?? 40 00 00 00 }                     // mov dword, 0x40

        // WriteProcessMemory - almost always present
        $wpm = "WriteProcessMemory" ascii wide

        // Key indicator: NtQueueApcThreadEx2 (rare in benign software)
        $ntqat_ex2 = "NtQueueApcThreadEx2" ascii wide

        // Special flag: QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 0x2 (or sometimes cast as 2)
        $special_flag1 = { 6A 02 }                            // push 2
        $special_flag2 = { C7 ?? 02 00 00 00 }               // mov dword, 2
        $special_flag3 = { 83 ?? 02 }                        // cmp dword, 2

    condition:
        // Must be a PE file
        uint16(0) == 0x5A4D and

        // At least one handle enumeration pattern
        (any of ($handle_enum*) or $ntqsi) and

        // RWX scanning indicators
        ( $vqe or any of ($protect_rwx, $hex_rwx) ) and

        // Writing to remote process
        $wpm and

        // The rarest and most suspicious: NtQueueApcThreadEx2 + special flag usage
        $ntqat_ex2 and any of ($special_flag*)
}

rule APC_Tandem_Primitive_Injection
{
    meta:
        author      = "0x12 Dark Development"
        date        = "2026-05-20"
        version     = "1.0"
        description = "Detects 'APC Tandem' style primitive injection: shellcode smuggled into a remote process via NtSetInformationThread(ThreadNameInformation) + GetThreadDescription APC + RtlMoveMemory APC, then executed through a Special User APC (NtQueueApcThreadEx2). Written to catch the technique pattern in general, not a single PoC."
        reference   = "https://0x12darkdev.net"
        category    = "process_injection"
        mitre       = "T1055"
        severity    = "high"

    strings:
        // --- Defining API triplet of the technique ---
        $api_apc_ex2     = "NtQueueApcThreadEx2"         ascii wide
        $api_get_desc    = "GetThreadDescription"        ascii wide
        $api_set_thread  = "NtSetInformationThread"      ascii wide

        // --- Supporting APIs commonly seen in the chain ---
        $api_rtl_move    = "RtlMoveMemory"               ascii wide
        $api_rtl_init    = "RtlInitUnicodeStringEx"      ascii wide
        $api_nt_query    = "NtQueryInformationProcess"   ascii wide
        $api_rpm         = "ReadProcessMemory"           ascii wide

        // --- ThreadNameInformation class id (0x26) loaded as an immediate ---
        $tni_b8          = { B8 26 00 00 00 }            // mov eax, 0x26
        $tni_b9          = { B9 26 00 00 00 }            // mov ecx, 0x26
        $tni_ba          = { BA 26 00 00 00 }            // mov edx, 0x26
        $tni_push        = { 6A 26 }                     // push 0x26
        $tni_mov_mem     = { C7 [1-6] 26 00 00 00 }      // mov dword [mem], 0x26

        // --- Special User APC flag literal when symbol name is kept ---
        $special_flag_lit = "QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC" ascii

        // --- Chunk-size constants forced by the 16-bit Length field of UNICODE_STRING ---
        $chunk_F000  = { B8 00 F0 00 00 }                // mov eax, 0xF000
        $chunk_C000  = { B8 00 C0 00 00 }                // mov eax, 0xC000
        $chunk_8000  = { B8 00 80 00 00 }                // mov eax, 0x8000

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and all of ($api_apc_ex2, $api_get_desc, $api_set_thread)
        and (
            any of ($tni_*)
            or any of ($chunk_*)
            or $special_flag_lit
            or 2 of ($api_rtl_move, $api_rtl_init, $api_nt_query, $api_rpm)
        )
}

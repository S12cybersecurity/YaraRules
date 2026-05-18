rule NtCreateThreadEx_ExitCode_Read_Primitive
{
    meta:
        description = "Detects tools that abuse NtCreateThreadEx and RtlQueryDepthSList to build a remote memory read primitive without calling ReadProcessMemory, collecting data via thread exit codes"
        author      = "0x12 Dark Development"
        date        = "2026-05-18"
        reference   = "https://trickster0.github.io/posts/Primitive-Injection/"
        technique   = "T1055 - Process Injection"
        severity    = "high"
        category    = "defense_evasion"

    strings:
        // Core undocumented thread creation API
        $api_ntcreatethreadex   = "NtCreateThreadEx"        ascii wide

        // The victim function used as a read gadget
        $gadget_rtlquery        = "RtlQueryDepthSList"      ascii wide

        // Exit code collection — mandatory for this primitive
        $api_getexitcode        = "GetExitCodeThread"       ascii wide

        // Thread synchronization — always present in the read loop
        $api_waitforsingle      = "WaitForSingleObject"     ascii wide

        // ntdll resolution at runtime — dynamic import pattern
        $api_getmodule          = "GetModuleHandleA"        ascii wide
        $api_getprocaddr        = "GetProcAddress"          ascii wide

        // Common companion APIs for the remote variant
        $api_openprocess        = "OpenProcess"             ascii wide
        $api_closehandle        = "CloseHandle"             ascii wide
        $api_heapalloc          = "HeapAlloc"               ascii wide

        // 2-byte stride loop pattern — i += 2 compiled as ADD reg, 2
        $stride_2byte_add       = { 83 C? 02 }             // add reg, 2
        $stride_2byte_lea       = { 8D ?? 02 }             // lea reg, [reg+2]

        // GENERIC_EXECUTE access mask passed to NtCreateThreadEx = 0x20000000
        $access_generic_exec    = { 00 00 00 20 }

        // HeapAlloc with HEAP_ZERO_MEMORY flag = 0x00000008
        $heap_zero_flag         = { 08 00 00 00 }

        // String markers from PoC / tooling variants
        $str_read_remote        = "cReadRemoteMemory"       ascii wide
        $str_read_attempt       = "Attempting to read"      ascii wide nocase
        $str_exitcode_label     = "ExitCode"                ascii wide

    condition:
        uint16(0) == 0x5A4D and         // MZ header — PE file
        filesize < 3MB and

        // Must use the undocumented thread creation API
        $api_ntcreatethreadex and

        // Must reference the specific ntdll gadget used as read primitive
        $gadget_rtlquery and

        // Must collect data via exit code — this is what makes it a read primitive
        $api_getexitcode and
        $api_waitforsingle and

        // Must resolve functions dynamically from ntdll at runtime
        ($api_getmodule and $api_getprocaddr) and

        // At least one additional indicator: stride pattern, access mask, or string marker
        (
            any of ($stride_2byte_add, $stride_2byte_lea) or
            $access_generic_exec or
            any of ($str_read_remote, $str_read_attempt, $str_exitcode_label)
        )
}

rule APC_Argument_Abuse_Write_Primitive
{
    meta:
        description = "Detects APC-based remote memory write primitive abusing ntdll routines (RtlFillMemory, RtlInitializeBitMapEx) as write gadgets via NtQueueApcThread/NtQueueApcThreadEx2"
        author = "0x12 Dark Development"
        date = "2026-05-14"
        reference = "https://trickster0.github.io/posts/Primitive-Injection/"
        severity = "high"
        category = "process_injection"
        technique = "T1055"
        
    strings:
        // Core NT APIs commonly imported by name or resolved dynamically
        $api_ntcreatethreadex     = "NtCreateThreadEx"        ascii wide nocase
        $api_ntqueueapc           = "NtQueueApcThread"        ascii wide nocase
        $api_ntqueueapcex         = "NtQueueApcThreadEx"      ascii wide nocase
        $api_ntqueueapcex2        = "NtQueueApcThreadEx2"     ascii wide nocase

        // Memory operation primitives used as write gadgets
        $gadget_fillmemory        = "RtlFillMemory"           ascii wide
        $gadget_bitmap            = "RtlInitializeBitMapEx"   ascii wide
        $gadget_exitthread        = "RtlExitUserThread"       ascii wide
        $gadget_copymemory        = "RtlCopyMemory"           ascii wide
        $gadget_zeromemory        = "RtlZeroMemory"           ascii wide
        $gadget_movememory        = "RtlMoveMemory"           ascii wide

        // Companion APIs typically chained with this primitive
        $api_virtualallocex       = "VirtualAllocEx"          ascii wide
        $api_openprocess          = "OpenProcess"             ascii wide
        $api_openthread           = "OpenThread"              ascii wide
        $api_resumethread         = "ResumeThread"            ascii wide
        $api_createsnapshot       = "CreateToolhelp32Snapshot" ascii wide

        // Special User APC flag value (NtQueueApcThreadEx2 variant)
        // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 0x2 — flag pushed as immediate
        $special_apc_flag_1       = { B? 02 00 00 00 }   // mov reg, 2
        $special_apc_flag_2       = { 6A 02 }            // push 2
        $alertable_apc_flag       = { B? 01 00 00 00 }   // mov reg, 1 (alertable)

        // String literal commonly seen in PoCs/tooling adapted from this primitive
        $str_pid_hardcode         = /pid\s*=\s*\d{2,6}/ ascii nocase
        $str_apc_marker           = "APC routines" ascii wide nocase
        $str_remote_write         = "WriteRemoteMemory" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and        // PE header (MZ)
        filesize < 5MB and

        // Must reference at least one APC queueing API
        (
            any of ($api_ntqueueapc*, $api_ntqueueapcex2)
        )
        and

        // Must reference at least one ntdll routine used as write gadget
        (
            2 of ($gadget_fillmemory, $gadget_bitmap, $gadget_exitthread, 
                  $gadget_copymemory, $gadget_zeromemory, $gadget_movememory)
        )
        and

        // Must combine with remote process operation APIs
        (
            $api_virtualallocex and
            ($api_openprocess or $api_openthread)
        )
        and

        // Either: classic variant (thread creation + resume)
        // Or:     Ex2 variant (Special User APC flag present)
        (
            ($api_ntcreatethreadex and $api_resumethread) or
            ($api_ntqueueapcex2 and any of ($special_apc_flag_1, $special_apc_flag_2)) or
            any of ($str_remote_write, $str_apc_marker)
        )
}

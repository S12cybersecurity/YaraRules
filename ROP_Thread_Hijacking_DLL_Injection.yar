rule ROP_Thread_Hijacking_DLL_Injection
{
    meta:
        description     = "Detects ROP-based DLL injection via thread context hijacking without executable memory allocation"
        author          = "0x12 Dark Development"
        reference       = "https://medium.com/@s12deff"
        technique       = "T(ROP)H - Thread Hijacking via ROP gadget to load DLL without RWX memory"

    strings:
        // Thread hijacking API combination
        $api_suspend    = "SuspendThread"      ascii wide
        $api_getctx     = "GetThreadContext"   ascii wide
        $api_setctx     = "SetThreadContext"   ascii wide
        $api_resume     = "ResumeThread"       ascii wide

        // Memory write into remote process (chain written to thread stack)
        $api_wpm        = "WriteProcessMemory" ascii wide

        // DLL loading — the goal of the injection
        $api_loadlib    = "LoadLibraryA"       ascii wide
        $api_loadlibw   = "LoadLibraryW"       ascii wide

        // Thread enumeration to find victim thread
        $api_snap       = "CreateToolhelp32Snapshot" ascii wide
        $api_thread32   = "Thread32First"      ascii wide

        // pop rcx ; ret — x64 calling convention gadget (arg1 → RCX)
        $gadget_rcx     = { 59 C3 }

        // pop rdx ; ret — x64 calling convention gadget (arg2 → RDX)
        $gadget_rdx     = { 5A C3 }

        // pop r8 ; ret — x64 calling convention gadget (arg3 → R8)
        $gadget_r8      = { 41 58 C3 }

        // pop r9 ; ret — x64 calling convention gadget (arg4 → R9)
        $gadget_r9      = { 41 59 C3 }

        // add rsp, 0x28 ; ret — shadow space alignment gadget
        $gadget_rsp28   = { 48 83 C4 28 C3 }

        // add rsp, 0x20 ; ret — shadow space alignment gadget (variant)
        $gadget_rsp20   = { 48 83 C4 20 C3 }

        // RSP adjustment pattern — sub rsp, N (stack pivot preparation)
        $rsp_sub        = { 48 83 EC ?? }

        // PE header walking — e_lfanew offset (0x3C) access pattern
        $pe_walk        = { 8B 40 3C }

        // .text section name — gadget scanner targets executable section
        $text_section   = ".text" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and

        // Core thread hijacking triad — must all be present
        all of ($api_suspend, $api_getctx, $api_setctx) and

        // Must write into remote process
        $api_wpm and

        // Must load a DLL — the injection goal
        any of ($api_loadlib, $api_loadlibw) and

        // Must have at least one ROP gadget byte sequence
        any of ($gadget_*) and

        // PE header walking OR thread enumeration — gadget scanner or thread finder
        (
            ($pe_walk and $text_section) or
            ($api_snap and $api_thread32)
        )
}

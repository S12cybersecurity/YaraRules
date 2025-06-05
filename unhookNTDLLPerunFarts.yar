rule Detect_Unhook_NTDLL_PerunFarts
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects unhooking of ntdll.dll using Perun Farts technique"
        date = "2025-06-05"

    strings:
        $sNtdll = "ntdll.dll"
        $sKernel32 = "kernel32.dll"
        $sVirtualProtect = "VirtualProtect"
        $pattern_syscall = { 0F 05 C3 }         // syscall; ret instruction pattern
        $pattern_breakpoints = { CC CC CC }     // Int3 breakpoints pattern
        $memcpy_call = "memcpy"

    condition:
        all of ($sNtdll, $sKernel32, $sVirtualProtect, $memcpy_call) and
        any of ($pattern_syscall, $pattern_breakpoints)
}

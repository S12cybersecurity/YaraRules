rule TROPH_DLL_Injection_ROP_Thread_Hijacking
{
    meta:
        description = "Detects ROP-based DLL injection via thread context hijacking"
        author      = "0x12 Dark Development"
        reference   = "https://medium.com/@s12deff"

    strings:
        // SuspendThread + GetThreadContext pattern
        $api1 = "SuspendThread"   ascii wide
        $api2 = "GetThreadContext" ascii wide
        $api3 = "SetThreadContext" ascii wide
        $api4 = "LoadLibraryA"    ascii wide

        // pop rcx ; ret gadget bytes
        $gadget = { 59 C3 }

        // WriteProcessMemory to thread stack
        $api5 = "WriteProcessMemory" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        all of ($api*) and
        $gadget
}

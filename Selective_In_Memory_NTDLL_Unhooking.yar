rule Selective_In_Memory_NTDLL_Unhooking
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects Selective In-Memory Syscall Unhooking techniques"
        version = "1.0"
        date = "2025-07-03"
        reference = "Inspired by known unhooking methods such as Perun's Fart and Hell's Gate"

    strings:
        // Common API usage
        $a1 = "ReadProcessMemory" nocase
        $a2 = "VirtualProtect" nocase
        $a3 = "FlushInstructionCache" nocase
        $a4 = "CreateProcess" nocase
        $a5 = "GetModuleInformation" nocase
        $a6 = "EnumProcessModulesEx" nocase

        // Heuristic syscall stub (mov r10, rcx; mov eax, imm32; syscall; ret)
        $b1 = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3 }

        // Checking for jump instructions (used to detect hooks)
        $c1 = { FF 25 ?? ?? ?? ?? } // JMP [rip+offset]
        $c2 = { E9 ?? ?? ?? ?? }    // JMP rel32
        $c3 = { EB ?? }             // JMP short

        // Indicators of in-memory PE parsing
        $d1 = "IMAGE_EXPORT_DIRECTORY" nocase
        $d2 = "AddressOfFunctions" nocase
        $d3 = "AddressOfNames" nocase
        $d4 = "e_lfanew" nocase

    condition:
        4 of ($a*) and 1 of ($b*) and any of ($c*) and any of ($d*)
}

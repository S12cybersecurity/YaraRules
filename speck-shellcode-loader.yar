rule SpeckShellcodeLoader
{
    meta:
        description = "Detects in-memory Speck-encrypted shellcode loader with VirtualAlloc + function pointer execution"
        author = "0x12 Dark Development"
        date = "2025-06-24"
        version = "1.0"
        reference = "https://cocomelonc.github.io/malware/2025/05/29/malware-cryptography-42.html"

    strings:
        // VirtualAlloc with execute permissions
        $a1 = "VirtualAlloc" wide ascii

        // Common flag: PAGE_EXECUTE_READWRITE (0x40)
        $a2 = { 6A 40 }                // push 0x40
        $a3 = { C7 45 ?? 40 00 00 00 } // mov [ebp+?], 0x40
        $a4 = { B8 00 00 00 00 }       // mov eax, offset (used before call VirtualAlloc)
        
        // Function pointer execution: call eax / call [reg] / cast style
        $b1 = { FF D0 }                // call eax
        $b2 = { FF 10 }                // call [eax]
        $b3 = { FF 15 ?? ?? ?? ?? }    // call [mem]

        // Optional: memcpy pattern (not reliable in optimized builds)
        $c1 = "memcpy" ascii wide

        // Optional: Speck key schedule signature (b = (ror + xor) loop)
        $d1 = { 48 0F C9 }             // ror rcx, 8 (typical start)
        $d2 = { 48 0F C1 }             // rol rcx, 3

    condition:
        uint16(0) == 0x5A4D and           // PE file
        $a1 and ($a2 or $a3) and          // VirtualAlloc + EXEC flag
        ($b1 or $b2 or $b3) and           // function pointer execution
        (1 of ($d1, $d2) or $c1)          // Speck pattern or memcpy (optional)
}

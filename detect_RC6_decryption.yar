rule Detect_RC6_Decryption
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects RC6 decryption function using common RC6 constants and patterns"
        date = "2025-06-25"
        version = "1.0"

    strings:
        // Common RC6 constants in little-endian hex (P32 and Q32)
        $p32 = { 63 51 E1 B7 }    // 0xB7E15163
        $q32 = { B9 79 37 9E }    // 0x9E3779B9

        // Rotate instructions for x86 (example patterns)
        $rol = { D3 C0 }           // rol eax, cl
        $ror = { D3 C8 }           // ror eax, cl

    condition:
        all of ($p32, $q32) and any of ($rol, $ror)
}

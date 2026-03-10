rule Layered_String_Obfuscation_Cloakwork_Style {
    meta:
        description = "Detects compile-time layered string encryption with runtime morphing capabilities"
        author = "0x12 Dark Development"
        technique = "Compile-time Obfuscation / String Encryption"
        reference = "Cloakwork 2.0 Template"
        date = "2026-03-10"

    strings:
        /* Constants used in the Knuth multiplicative hash and xorshift64* These are common in high-quality entropy generators for obfuscators.
        */
        $entropy_const_1 = { 15 7C 4A 7F B9 79 37 9E } // 0x9e3779b97f4a7c15
        $entropy_const_2 = { EB 11 31 13 BB 49 D0 94 } // 0x94d049bb133111eb
        $entropy_const_3 = { 1D DD 6C 4F 91 F4 45 25 } // 0x2545F4914F6CDD1D

        /* Pattern for the decryption loop logic:
           Typically involves an XOR, a bitwise rotation (ROR/ROL), 
           and an index-based transformation (like i*i + i).
        */
        $decryption_logic = { 
            8B ??                // mov reg, [index/counter]
            0F AF ??             // imul reg, reg (i * i)
            03 ??                // add reg, reg (+ i)
            33 ??                // xor reg, [data] (Apply Layer 3)
            D3 C?                // ror/rol reg, cl (Apply Layer 2)
            33 ??                // xor reg, [key] (Apply Layer 1)
        }

        /* The 'Morphing' logic:
           Detects the periodic re-encryption check (cnt % 10).
        */
        $morph_modulo = { 
            B? 0A 00 00 00       // mov reg, 10 (0xA)
            F7 ??                // idiv/div (modulo operation)
            83 ?? 00             // cmp reg, 0
            75 ??                // jne (skip if not 10th access)
        }

    condition:
        uint16(0) == 0x5A4D and // PE File
        (
            2 of ($entropy_const*) or 
            ($decryption_logic and $morph_modulo)
        )
}

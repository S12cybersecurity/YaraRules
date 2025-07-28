rule RC5_Shellcode_Encryption
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects usage of RC5 block encryption routine, likely for shellcode encryption"
        version = "1.0"

    strings:
        // Look for the sequence: A = rotate_left((A ^ B), B) + subkey
        $rol_xor_add_1 = { 8B ?? 33 ?? C1 C0 ?? 03 ?? }   // mov, xor, rol, add
        $rol_xor_add_2 = { 33 ?? C1 C0 ?? 03 ?? }         // xor, rol, add (shorter variant)
        
        // Look for use of rotate_left and XOR in loop structure
        $rc5_loop_signature = { 
            33 ??         // xor reg, reg
            C1 C0 ??      // rol reg, imm or reg
            03 ??         // add reg, reg/mem
            33 ??         // xor reg, reg
            C1 C0 ??      // rol reg, imm or reg
            03 ??         // add reg, reg/mem
        }

        // Optional: subkey setup pattern (S[0] = 0xb7e15163, S[i] += 0x9e3779b9)
        $key_schedule_constant = { 63 51 E1 B7 } // Little endian of 0xB7E15163
        $key_schedule_delta = { B9 77 37 9E }    // Little endian of 0x9E3779B9

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        (
            2 of ($rol_xor_add_*) or
            $rc5_loop_signature
        ) and
        1 of ($key_schedule_constant, $key_schedule_delta)
}

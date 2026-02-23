rule Speck_CBC_KeyWrapping_Shellcode_Loader
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects Speck block cipher usage with CBC mode and session key wrapping — common in custom shellcode loaders/encryptors"
        category    = "malware/crypter"
        reference   = "https://cocomelonc.github.io/malware/2025/05/29/malware-cryptography-42.html"
        date        = "2026-02-23"

    strings:
        // ── Speck-128 rotation constants (ROL 3 / ROR 8) ──────────────────
        // These are the defining operations of Speck-128 key schedule and round function.
        // Compiler usually emits these as immediate shift values in tight loops.

        // ROR 8 on 64-bit: shr rax, 8 + shl rcx, 56 pattern (or ror rax, 8)
        $speck_ror8_x64   = { 48 C1 E? 08 }   // shr/shl reg64, 8
        $speck_rol3_x64   = { 48 C1 E? 03 }   // shr/shl reg64, 3
        $speck_ror8_x86   = { C1 E? 08 }       // shr/shl reg32, 8
        $speck_rol3_x86   = { C1 E? 03 }       // shr/shl reg32, 3

        // ── CRC32 software table-driven implementation ─────────────────────
        // The standard reflected polynomial 0xEDB88320 — appears as a 32-bit
        // immediate in the conditional XOR inside the table generation loop.
        $crc32_poly       = { 20 83 B8 ED }    // 0xEDB88320 little-endian

        // CRC32 init value 0xFFFFFFFF and final XOR (same value)
        $crc32_init       = { FF FF FF FF }

        // ── CBC mode XOR-before-encrypt pattern ───────────────────────────
        // block[0] ^= prev[0]; block[1] ^= prev[1]; before calling encrypt
        // Results in back-to-back 64-bit XOR instructions on memory operands
        $cbc_xor_x64      = { 48 33 ?? ?? ?? ?? ?? 48 33 ?? ?? ?? ?? ?? }

        // ── Key wrapping pattern ───────────────────────────────────────────
        // Session key encrypted with master key (ECB, single block).
        // Typically: two sequential speckEncrypt calls or a single ECB call
        // before the main CBC loop. We look for two consecutive encrypt
        // round-loop entries within close range.

        // ── Blob header layout fingerprint ────────────────────────────────
        // BLOB_PAYLOAD_OFFSET = 36 (0x24): memcpy(..., buf+36, ...) appears
        // as an add/lea with immediate 0x24 feeding into a memcpy/mov sequence
        $blob_offset_36   = { 83 C? 24 }       // add reg, 0x24
        $blob_offset_36b  = { 8D ?? 24 }       // lea reg, [reg+0x24]

        // ── Blob header: IV at offset 16 (0x10) ───────────────────────────
        $blob_offset_16   = { 83 C? 10 }       // add reg, 0x10
        $blob_offset_16b  = { 8D ?? 10 }       // lea reg, [reg+0x10]

        // ── rand() seeded with time(NULL) — common IV/key generation ──────
        $srand_time       = { FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }  // call time; push eax; call srand

        // ── calloc(1, n) + memcpy pattern — padded buffer allocation ──────
        $calloc_1         = { 6A 01 }          // push 1  (calloc first arg)

        // ── Strings / debug artifacts that survive stripped binaries ───────
        $str_session_key  = "Session key" ascii wide nocase
        $str_wrapped_key  = "Wrapped" ascii wide nocase
        $str_crc32_ok     = "CRC32" ascii wide nocase
        $str_decrypt_ok   = "Decryption OK" ascii wide nocase
        $str_decrypt_fail = "Decryption FAIL" ascii wide nocase
        $str_encrypt_mode = "ENCRYPT_MODE" ascii wide
        $str_decrypt_mode = "DECRYPT_MODE" ascii wide

    condition:
        uint16(0) == 0x5A4D  // MZ header — PE file

        and filesize < 5MB

        and (
            // Confident hit: rotation constants + CRC polynomial + CBC XOR
            (
                ( $speck_ror8_x64 and $speck_rol3_x64 ) or
                ( $speck_ror8_x86 and $speck_rol3_x86 )
            )
            and $crc32_poly
            and $cbc_xor_x64
        )

        or (
            // Debug/non-stripped binary with telltale strings
            2 of ($str_session_key, $str_wrapped_key, $str_crc32_ok,
                  $str_decrypt_ok, $str_decrypt_fail)
            and $crc32_poly
        )

        or (
            // Blob layout fingerprint: both key offset (0x10) and
            // payload offset (0x24) present alongside Speck rotations
            ( $blob_offset_36 or $blob_offset_36b )
            and ( $blob_offset_16 or $blob_offset_16b )
            and ( $speck_ror8_x64 or $speck_ror8_x86 )
            and $crc32_poly
        )
}

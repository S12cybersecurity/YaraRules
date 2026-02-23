rule CompileTime_XOR_String_Encryption
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects compile-time XOR string encryption/obfuscation patterns in compiled binaries"
        reference   = "https://0x12darkdev.net"
        date        = "2026-02-23"
        version     = "1.0"
        confidence  = "medium"

    strings:
        // Common std::mutex + std::atomic patterns left in RTTI/symbols
        $rtti_mutex     = "mutex" ascii wide
        $rtti_atomic    = "atomic" ascii wide
        $rtti_array     = "index_sequence" ascii wide

        // Template instantiation artifacts in unstripped binaries
        $tmpl1 = "EncryptedString" ascii wide
        $tmpl2 = "encrypted_string" ascii nocase wide
        $tmpl3 = "key_for" ascii wide

        // XOR loop over sequential indices is often compiled into
        // repeated xor + increment patterns — common byte sequences
        // for small unrolled XOR loops in x64
        $xor_loop1 = { 30 [1-4] 48 FF C? [0-4] 30 [1-4] 48 FF C? }
        $xor_loop2 = { 32 [1-2] 80 F? ?? [0-3] 48 83 C? 01 }

        // double-checked locking pattern:
        // test + je + lock cmpxchg or mov + test again
        $dcl1 = { 84 C0 75 ?? F0 [0-8] 84 C0 }
        $dcl2 = { 85 C0 74 ?? F0 [0-8] 85 C0 }

        // High density of non-printable bytes in .rdata (encrypted strings)
        $enc_marker = { [2-4] ( [0x00-0x08] | [0x0E-0x1F] | [0x80-0xFF] ) 
                        [2-4] ( [0x00-0x08] | [0x0E-0x1F] | [0x80-0xFF] )
                        [2-4] ( [0x00-0x08] | [0x0E-0x1F] | [0x80-0xFF] ) }

    condition:
        uint16(0) == 0x5A4D  // valid PE file
        and filesize < 10MB
        and (
            // Unstripped binary — symbol names still present
            (2 of ($tmpl*, $rtti*))
            or
            // Stripped binary — detect by behavior patterns
            (
                (#xor_loop1 > 2 or #xor_loop2 > 2)
                and 1 of ($dcl*)
                and $enc_marker
            )
        )
}

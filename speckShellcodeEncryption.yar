rule Speck_Encryption_Detector
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects Speck block cipher implementation in CBC mode (generic, no fixed key)"
        reference = "https://cocomelonc.github.io/malware/2025/05/29/malware-cryptography-42.html"
        date = "2025-06-18"
        version = "1.0"

    strings:
        // Function names typically found in Speck cipher implementations
        $rol_func = "uint64_t rol(uint64_t x, int r)"
        $ror_func = "uint64_t ror(uint64_t x, int r)"
        $key_schedule = "void speckKeySchedule(uint64_t key[2])"
        $encrypt_func = "void speckEncrypt(uint64_t* x, uint64_t* y)"
        $decrypt_func = "void speckDecrypt(uint64_t* x, uint64_t* y)"

        // CBC mode encryption pattern hint (xor with previous block)
        $cbc_xor = /(\^\s*prev\[\d\])/

    condition:
        // Detect presence of at least 4 of the main Speck-related functions and CBC xor pattern
        4 of ($rol_func, $ror_func, $key_schedule, $encrypt_func, $decrypt_func) and
        $cbc_xor
}

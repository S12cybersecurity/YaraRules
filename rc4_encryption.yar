rule RC4_Shellcode_Encryption
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects RC4 encryption logic used for shellcode obfuscation"
        date = "2025-07-22"
        reference = "https://medium.com/@0x12DarkDev" // optional

    strings:
        // Function markers and patterns commonly found in the RC4 implementation
        $ksa = "void KSA(unsigned char* s, unsigned char* key" ascii
        $prga = "unsigned char* PRGA(unsigned char* s, unsigned int len" ascii
        $rc4func = "unsigned char* RC4(unsigned char* plaintext" ascii
        $swap = "void swap(unsigned char* a, unsigned char* b" ascii
        $xor_comment = "XOR with keystream" ascii

    condition:
        3 of ($ksa, $prga, $rc4func, $swap, $xor_comment)
}

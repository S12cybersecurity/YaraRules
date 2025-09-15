rule CXX_Constexpr_XOR_String_Obfuscation
{
  meta:
    author = "0x12 Dark Development"
    description = "Source-level: constexpr precomputation + XOR-based string decode"
    confidence = "high (source only)"
  strings:
    $kw1 = "constexpr" ascii
    $kw2 = "template<" ascii
    $kw3 = "const char(&" ascii
    $kw4 = "uint8_t" ascii
    $xor1 = "^" ascii
    $dec1 = "decrypt" ascii nocase
    $erase = "secure_erase" ascii nocase
    $hint1 = "compile-time" ascii nocase
    $hint2 = "encrypted" ascii nocase
  condition:
    // Look for constexpr + XOR + a byte container + a named decrypt routine
    $kw1 and $xor1 and $kw4 and $dec1 and ($kw2 or $kw3 or $erase or $hint1 or $hint2)
}

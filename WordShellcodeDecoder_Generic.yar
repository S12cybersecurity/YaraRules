/*
  Rule   : WordShellcodeDecoder_Generic
  Author : 0x12 Dark Development
  Description:
    Detects binary loaders that implement a word-based shellcode decoding scheme.
    The technique maps English words to byte values through a 256-entry lookup
    table, tokenizes a plaintext payload using punctuation/whitespace separators,
    and reconstructs raw shellcode byte-by-byte from the token stream.
    Rule is intentionally generic and does not target any specific tool.
  Reference: https://github.com/NirvanaOn/NOW
             https://github.com/tehstoni/LexiCrypt
             https://github.com/wsummerhill/DictionShellcode
*/

rule WordShellcodeDecoder_Generic {

    meta:
        author      = "0x12 Dark Development"
        description = "Detects binary loaders using a word-to-byte mapping table to decode shellcode from natural language text"
        category    = "evasion, encoding, shellcode-delivery"
        technique   = "T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File"
        severity    = "high"
        date        = "2025-08-01"

    strings:
        /*
         * Separator sets used by tokenizers.
         * The common denominator across all implementations is whitespace +
         * the basic sentence punctuation set. We match several ordering variants.
         */
        $sep_full   = " \t\n\r,.;:!?()[]{}\"'-"     ascii wide
        $sep_min    = " \t\n\r,.;:!?"               ascii wide
        $sep_ws_pun = " .,;:!?\t\n"                 ascii wide

        /*
         * Canonical RC4 KSA initialisation pattern (inline, not imported).
         * Byte sequence: for(i=0;i<256;i++) S[i]=i
         * Compiled as: xor eax,eax / mov [base+rax], al / inc eax / cmp eax,100h
         * This 6-byte sequence is highly characteristic and rarely a false positive.
         */
        $rc4_ksa    = { 31 C0 88 04 08 FF C0 3D 00 01 00 00 }

        /*
         * RC4 PRGA inner loop — swap + keystream output.
         * Matches the two-swap + index add pattern regardless of register allocation.
         */
        $rc4_prga   = { 8A ?? ?? 86 ?? ?? 88 ?? ?? 03 ?? ?? 8A ?? ?? }

        /*
         * Fisher-Yates shuffle driven by a keystream byte.
         * Pattern: ks % (i+1) followed by a swap of two array elements.
         * Captured as: movzx + idiv/imul + xchg sequence (32-bit variant).
         */
        $fy_shuffle = { 0F B6 ?? F7 ?? 8B ?? 87 ?? }

        /*
         * Byte accumulation loop pattern: result of lookup written into
         * a growing output buffer indexed by a counter.
         * mov [buf + counter], al  (general form, tolerates base-reg variation)
         */
        $accum_byte = { 88 04 ?? 48 FF C? }

        /*
         * isalpha / tolower pipeline — used to clean tokens before lookup.
         * Nearly all implementations normalise tokens to lowercase alpha-only.
         * Inline pattern: call isalpha followed closely by call tolower.
         */
        $clean_tok  = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF 15 ?? ?? ?? ?? }

        /*
         * strtok import name — present in any MSVC/MinGW build that does
         * not hand-roll the tokenizer.
         */
        $strtok_imp = "strtok" ascii nocase

        /*
         * Padding pool — natural English words that appear in word-pool arrays.
         * Any two from this set appearing close together inside a binary
         * (not in a normal string table) is a strong signal of a codebook.
         */
        $pool_w1    = "however"   ascii fullword
        $pool_w2    = "therefore"  ascii fullword
        $pool_w3    = "moreover"   ascii fullword
        $pool_w4    = "furthermore" ascii fullword
        $pool_w5    = "nevertheless" ascii fullword
        $pool_w6    = "consequently" ascii fullword
        $pool_w7    = "alternatively" ascii fullword
        $pool_w8    = "additionally" ascii fullword
        $pool_w9    = "particularly" ascii fullword
        $pool_w10   = "subsequently" ascii fullword

    condition:
        /* PE or raw binary */
        (
            uint16(0) == 0x5A4D     /* MZ header */
            or uint32(0) == 0x464C457F /* ELF header */
        )
        and filesize < 10MB

        /* Core decoder fingerprint:
           separator string + token accumulation + import or inline tokenizer */
        and (
            ($sep_full or $sep_min or $sep_ws_pun)
            and $accum_byte
            and ($strtok_imp or $clean_tok)
        )

        /* Cipher layer — inline RC4 KSA or PRGA, or the Fisher-Yates shuffle */
        and (
            $rc4_ksa or $rc4_prga or $fy_shuffle
        )

        /* Codebook presence:
           4 or more connector/padding words clustered inside the binary.
           These only appear together in files that embed a 256-word pool. */
        and (
            4 of ($pool_w*)
        )
}

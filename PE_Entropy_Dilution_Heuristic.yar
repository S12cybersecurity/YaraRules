rule PE_Entropy_Dilution_Heuristic
{
    meta:
        description = "Detects likely entropy dilution via large null sections or word padding in .rdata"
        author      = "S12 - 0x12 Dark Development"
        reference   = "https://medium.com/@s12deff"

    condition:
        uint16(0) == 0x5A4D                      // MZ header
        and (
            // Large section with near-zero entropy (null/byte padding)
            for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].raw_size > 32768
                and pe.sections[i].entropy < 0.5
            )
            or
            // One section is high entropy, another is suspiciously large and low
            (
                for any i in (0..pe.number_of_sections - 1):
                (
                    pe.sections[i].entropy > 7.0
                )
                and for any j in (0..pe.number_of_sections - 1):
                (
                    pe.sections[j].raw_size > 65536
                    and pe.sections[j].entropy < 4.0
                )
            )
        )
}

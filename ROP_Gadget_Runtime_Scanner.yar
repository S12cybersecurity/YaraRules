rule ROP_Gadget_Runtime_Scanner
{
    meta:
        description = "Detects runtime ROP gadget scanning via PE section walking in loaded Windows DLLs"
        author      = "0x12 Dark Development"
        reference   = "https://medium.com/@s12deff"
        technique   = "Runtime gadget resolution by scanning .text section of loaded DLLs"

    strings:
        // DLL resolution — try loaded first, fallback to load
        $api_getmodule  = "GetModuleHandleA" ascii wide
        $api_loadlib    = "LoadLibraryA"     ascii wide

        // PE header walking — access e_lfanew at offset 0x3C
        $pe_lfanew      = { 8B 40 3C }

        // IMAGE_FIRST_SECTION macro pattern — NT headers + size of headers
        $pe_section     = { 48 8D 84 ?? ?? ?? ?? ?? }

        // .text section name comparison target
        $text_section   = ".text" ascii

        // memcmp loop pattern — comparing bytes in a loop (gadget scan)
        $scan_loop      = { 48 FF C? [0-8] 48 3B ?? }

        // Common x64 gadgets searched at runtime
        $gadget_pop_rcx = { 59 C3 }          // pop rcx ; ret
        $gadget_pop_rdx = { 5A C3 }          // pop rdx ; ret
        $gadget_pop_r8  = { 41 58 C3 }       // pop r8  ; ret
        $gadget_pop_r9  = { 41 59 C3 }       // pop r9  ; ret
        $gadget_rsp28   = { 48 83 C4 28 C3 } // add rsp, 0x28 ; ret
        $gadget_rsp20   = { 48 83 C4 20 C3 } // add rsp, 0x20 ; ret

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and

        // Must resolve DLL at runtime
        $api_getmodule and
        $api_loadlib and

        // Must walk PE headers to find sections
        $pe_lfanew and

        // Must target .text section by name
        $text_section and

        // Must contain at least 2 gadget sequences — scanner carries its targets
        2 of ($gadget_*)
}

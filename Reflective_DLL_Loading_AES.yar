rule Reflective_DLL_Loading_Generic
{
    meta:
        description = "Detects generic reflective DLL / manual PE loading techniques"
        author = "0x12 Dark Development"
        research_purpose = "Academic research"
        date = "2026-03-03"
        technique = "Reflective DLL Loading / Manual PE Mapping"

    strings:

        // PE parsing structures commonly referenced together
        $mz = "MZ" ascii
        $pe = "PE\0\0" ascii

        // PE structure strings sometimes embedded in debug/symbol builds
        $s1 = "IMAGE_DOS_HEADER" ascii
        $s2 = "IMAGE_NT_HEADERS" ascii
        $s3 = "IMAGE_EXPORT_DIRECTORY" ascii

        // Common reflective loader export name (not required but useful)
        $refldr = "ReflectiveLoader" ascii wide

        // Manual export walking logic indicators
        $exp1 = "AddressOfNames" ascii
        $exp2 = "AddressOfFunctions" ascii
        $exp3 = "AddressOfNameOrdinals" ascii

        // Memory execution pattern APIs
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "CreateThread" ascii wide
        $api3 = "WriteProcessMemory" ascii wide

        // Crypto usage often paired with encrypted loaders
        $crypto1 = "CryptAcquireContext" ascii wide
        $crypto2 = "CryptDeriveKey" ascii wide
        $crypto3 = "CryptDecrypt" ascii wide

    condition:

        // Must reference executable memory allocation
        $api1 and $api2 and

        // And show signs of PE header parsing
        (
            2 of ($s*) or
            2 of ($exp*) or
            $refldr
        )

        // Optional strengthening condition:
        and (1 of ($crypto*) or $api3)
}

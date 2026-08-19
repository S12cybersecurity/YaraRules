rule APIHashing_ExportWalk {
    meta:
        description = "Generic API hashing detector, export table walking, algorithm and resolution method agnostic"
        author      = "0x12 Dark Development"
        date        = "2026-08-19"

    strings:
        // Module base resolution
        // PEB direct x64 - gs:[60h], any GPR destination
        $peb_x64    = { 65 48 8B ?? 25 60 00 00 00 }

        // PEB direct x86 - fs:[30h]
        $peb_x86    = { 64 8B ?? 30 00 00 00 }

        // Via NtQueryInformationProcess(ProcessBasicInformation=0) → PebBaseAddress
        $nqip       = "NtQueryInformationProcess" ascii

        // PE header parsing
        // e_lfanew at DOS+0x3C, mandatory entry point for any PE walk
        $elfanew    = { 8B ?? 3C }

        // DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        //   x64 PE: NTHeader + 0x88 (0x18 FileHeader + 0x70 to DataDirectory[0])
        //   x86 PE: NTHeader + 0x78 (0x18 FileHeader + 0x60 to DataDirectory[0])
        $expdir_x64 = { 8B [1-2] 88 00 00 00 }
        $expdir_x86 = { 8B [1-2] 78 00 00 00 }

        // IMAGE_EXPORT_DIRECTORY field accesses
        // NumberOfFunctions at +0x14 (loop bound)
        $nof        = { 8B ?? 14 }

        // AddressOfFunctions at +0x1C
        $aof        = { 8B ?? 1C }

        // AddressOfNames at +0x20
        $aon        = { 8B ?? 20 }

        // AddressOfNameOrdinals at +0x24, WORD array, always accessed via movzx
        // this is the most distinctive pattern: 0F B7 is MOVZX r32, r/m16
        $aono       = { 0F B7 ?? 24 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and

        // must resolve module base without standard imports
        (any of ($peb_x64, $peb_x86, $nqip)) and

        // must parse PE from scratch
        $elfanew and
        (any of ($expdir_x64, $expdir_x86)) and

        // ordinal WORD access is the most specific export-loop indicator,
        // require it plus at least 2 other export dir field accesses
        $aono and 2 of ($nof, $aof, $aon)
}

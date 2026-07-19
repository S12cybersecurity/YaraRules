rule PEB_Loader_List_Manipulation
{
    meta:
        description = "Detects binaries that read and write PEB loader list structures in remote processes"
        author      = "0x12 Dark Development"
        category    = "defense_evasion"

    strings:
        $f1 = "NtQueryInformationProcess" ascii wide
        $f2 = "ReadProcessMemory"         ascii wide
        $f3 = "WriteProcessMemory"        ascii wide
        $f4 = "OpenProcess"               ascii wide

        // PEB->Ldr offset (0x18) read pattern, commonly compiled as a byte-immediate add
        $peb_ldr = { 48 83 C? 18 }

    condition:
        uint16(0) == 0x5A4D and
        all of ($f*) and
        $peb_ldr
}

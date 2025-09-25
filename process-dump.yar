import "pe"

rule WIN_MiniDump_DbgHelp_Importer
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects PE files that import MiniDumpWriteDump from dbghelp.dll"
        version     = "1.0"
        date        = "2025-09-25"
        reference   = "Detects explicit DbgHelp-based minidump capability"
    tags = ["windows", "minidump", "dbghelp", "dfir", "edr"]

    condition:
        uint16(0) == 0x5A4D and pe.is_pe and
        pe.imports("dbghelp.dll", "MiniDumpWriteDump")
}

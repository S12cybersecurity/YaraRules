rule GhostFile_Detection_0x12_DarkDev
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects ghost files loaded in memory with PE headers"
        version = "1.0"
        date = "2025-05-27"
        category = "memory"
        technique = "FILE_FLAG_DELETE_ON_CLOSE with section mapping"
        note = "Intended for use with memory scanners that can detect if file is NOT mapped from existing disk path (ghost file)"

    strings:
        $mz = { 4D 5A }         // 'MZ' header for PE files
        $pe = { 50 45 00 00 }   // 'PE\0\0' signature

    condition:
        $mz at 0 and
        uint32(0x3C) < filesize and
        $pe at uint32(0x3C)
}

rule GhostlyHollowing_Attempt
{
    meta:
        description = "Detects potential Ghostly Hollowing behavior using delete-pending file and remote section mapping"
        author = "0x12 Dark Development"
        date = "2025-05-21"
        technique = "Ghostly Hollowing"
        reference = "https://captain-woof.medium.com/ghostly-hollowing-probably-the-most-bizarre-windows-process-injection-technique-i-know-bf833c96663a"

    strings:
        $api1 = "NtMapViewOfSection" ascii
        $api2 = "MapViewOfFile2" ascii
        $api3 = "GetThreadContext" ascii
        $api4 = "SetThreadContext" ascii
        $api5 = "WriteProcessMemory" ascii
        $api6 = "CreateFileMappingW" ascii
        $flag  = "FILE_FLAG_DELETE_ON_CLOSE" ascii
        $pebWrite = { 64 89 05 ?? ?? ?? ?? }  // Possible PEB write (x64 pattern)

    condition:
        4 of ($api*) and
        filesize < 1MB and
        uint16(0) == 0x5A4D and
        $flag and
        $pebWrite
}

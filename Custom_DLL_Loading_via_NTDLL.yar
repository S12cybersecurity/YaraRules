rule Custom_DLL_Loading_via_NTDLL
{
    meta:
        description = "Detects custom DLL loading techniques using internal NTDLL loader functions"
        author = "0x12 Dark Development"
        technique = "Custom LoadLibrary / LdrLoadDll usage"
        category = "Defense Evasion / Loader"
        version = "1.0"

    strings:
        $ntdll_str       = "ntdll.dll" ascii nocase
        $ldrload_str     = "LdrLoadDll" ascii
        $rtlunicode_str  = "RtlInitUnicodeString" ascii

        // Common API resolution patterns
        $getproc_str     = "GetProcAddress" ascii
        $getmodule_str   = "GetModuleHandle" ascii

        // Optional UNICODE_STRING structure indicators
        $unicode_struct1 = "_UNICODE_STRING" ascii
        $unicode_struct2 = "UNICODE_STRING" ascii

    condition:
        all of ($ldrload_str, $rtlunicode_str, $ntdll_str) and
        1 of ($getproc_str, $getmodule_str) and
        any of ($unicode_struct*)
}

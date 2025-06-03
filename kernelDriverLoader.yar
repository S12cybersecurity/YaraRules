rule Temporary_Driver_Injection
{
    meta:
        description = "Detects kernel driver injection using NtLoadDriver with a temporary file"
        author = "0x12 Dark Development"
        technique = "Temporary Driver Injection"
        reference = "https://maldev.example.com/temp-driver-injection"

    strings:
        $reg_key     = "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
        $image_path  = "\\??\\C:\\Users\\" wide ascii
        $temp_hint   = "\\AppData\\Local\\Temp\\" wide ascii
        $ntloaddriver = "NtLoadDriver" ascii
        $sys_ext     = ".sys" ascii
        $drv_prefix  = "DRV" ascii

    condition:
        all of them
}

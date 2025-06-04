rule Fileless_Driver_Loading_Section_Object
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects driver loading via NtCreateSection and NtLoadDriver without leaving file traces on disk"
        date = "2025-06-04"
        technique = "Fileless Driver Load via Section Object"
        reference = "https://maldevacademy.com"

    strings:
        $s1 = "NtCreateSection" wide ascii
        $s2 = "NtLoadDriver" wide ascii
        $s3 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" wide ascii
        $s4 = "\\??\\" wide ascii
        $s5 = "SE_LOAD_DRIVER_NAME" wide ascii
        $s6 = "SEC_IMAGE" ascii
        $s7 = "ImagePath" wide ascii
        $s8 = "SERVICE_KERNEL_DRIVER" ascii

    condition:
        uint16(0) == 0x5A4D and // PE file magic
        4 of ($s*)
}

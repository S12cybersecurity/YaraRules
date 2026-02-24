rule BYOVD_Process_Termination_Tool_Generic
{
    meta:
        description = "Detects potential BYOVD userland tools abusing IOCTLs for arbitrary process termination"
        author = "0x12 Dark Development"
        reference = "Generic detection for BYOVD-based process kill primitives"
        date = "2026-02-24"
        category = "offensive-security"

    strings:
        $device_prefix = "\\\\.\\"
        $createfileA = "CreateFileA" ascii wide
        $createfileW = "CreateFileW" ascii wide
        $deviceiocontrol = "DeviceIoControl" ascii wide
        $ioctl_string = "IOCTL" ascii wide
        $kill_string1 = "TerminateProcess" ascii wide
        $kill_string2 = "kill process" ascii wide nocase
        $driver_string = "Driver" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        $device_prefix and
        $deviceiocontrol and
        1 of ($createfileA, $createfileW) and
        2 of ($ioctl_string, $kill_string1, $kill_string2, $driver_string)
}

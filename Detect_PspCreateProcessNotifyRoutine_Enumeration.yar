rule Detect_PspCreateProcessNotifyRoutine_Enumeration
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects binaries that attempt to enumerate PspCreateProcessNotifyRoutine kernel callbacks via BYOVD read primitives"
        date        = "2026-04-21"
        tags        = "kernel, byovd, edr-evasion, callback-enumeration"

    strings:
        // NtQuerySystemInformation with SystemModuleInformation (class 11)
        $ntqsi = "NtQuerySystemInformation" ascii wide

        // Vulnerable driver device names commonly used for read primitives
        $dev_gio     = "\\\\.\\GIO" ascii wide
        $dev_rtcore  = "\\\\.\\RTCore64" ascii wide
        $dev_physmem = "\\\\.\\PhysicalMemory" ascii wide
        $dev_gdrv    = "\\\\.\\GDrv" ascii wide

        // Kernel symbol strings sometimes referenced at runtime
        $sym1 = "PspCreateProcessNotifyRoutine" ascii wide
        $sym2 = "ntoskrnl.exe" ascii wide nocase

        // DeviceIoControl pattern used to send IOCTL read primitives
        $ioctl = "DeviceIoControl" ascii wide

        // Pointer decode pattern: callback & ~((1ULL << 3) + 0x1) = & ~0x9
        // Compiled usually to: and rax, FFFFFFFFFFFFFFF6
        $decode_ptr = { 48 83 E? F6 }

        // 0xffff000000000000 mask used to fix truncated kernel addresses
        $ffff_mask = { 00 00 00 00 00 00 FF FF }

        // Loop over 64 entries (0x40 = 64 in hex, common in compiled loops)
        $loop_64 = { 83 F? 40 }

    condition:
        uint16(0) == 0x5A4D and         // PE file
        $ntqsi and
        $ioctl and
        (1 of ($dev_*)) and
        $sym2 and
        2 of ($decode_ptr, $ffff_mask, $loop_64, $sym1)
}

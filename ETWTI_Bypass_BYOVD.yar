rule ETWTI_Bypass_BYOVD
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects binaries attempting to disable the ETW Threat Intelligence provider via kernel memory manipulation. Covers BYOVD-based patching of ProviderEnableInfo.IsEnabled through the EtwThreatIntProvRegHandle pointer chain."
        reference   = "https://0x12darkdev.net"
        date        = "2025"
        version     = "1.0"

    strings:
        // ETW TI provider GUID — unique identifier for the TI provider,
        // present in tools that target it explicitly
        $guid_str = "F4E1897C-BB5D-5668-F1D8-040F4D8DD344" ascii wide nocase

        // Binary form of the TI provider GUID (little-endian)
        $guid_bin = { 7C 89 E1 F4 5D BB 68 56 F1 D8 04 0F 4D 8D D3 44 }

        // Symbol name lookups targeting the ETW TI global handle
        $sym1 = "EtwThreatIntProvRegHandle" ascii wide
        $sym2 = "EtwThreatIntProvider"      ascii wide

        // Common kernel module enumeration via NtQuerySystemInformation
        // used to resolve ntoskrnl base — class 11 = SystemModuleInformation
        $ntqsi = "NtQuerySystemInformation" ascii wide

        // Known BYOVD device paths used as kernel R/W primitives
        $dev1 = "\\\\.\\GIO"       ascii wide
        $dev2 = "\\\\.\\RTCore64"  ascii wide
        $dev3 = "\\\\.\\gdrv"      ascii wide
        $dev4 = "\\\\.\\Nal"       ascii wide

        // IOCTL codes for common BYOVD kernel R/W primitives
        // GIO driver (loldrivers: 2bea1bca-753c-4f09-bc9f-566ab0193f4a)
        $ioctl_gio     = { 08 28 50 C3 }
        // RTCore64 (CVE-2019-16098)
        $ioctl_rtcore  = { 04 20 50 C3 }

        // Kernel address range lower bound check — canonical pattern
        // for IsValidKernelAddress: cmp rax, 0xFFFF000000000000
        $kaslr_check = { 48 B8 00 00 00 00 00 00 FF FF }

        // Zero-write pattern to a computed kernel address —
        // xor reg, reg followed by a kernel memory write call
        $zero_write1 = { 33 C0 FF 15 ?? ?? ?? ?? }
        $zero_write2 = { 48 33 C0 FF 15 ?? ?? ?? ?? }

        // ProviderEnableInfo offset 0x060 from _ETW_GUID_ENTRY
        // add rax/rcx/rdx, 0x60 patterns
        $offset_pei1 = { 48 83 C0 60 }
        $offset_pei2 = { 48 83 C1 60 }
        $offset_pei3 = { 48 83 C2 60 }

        // GuidEntry offset 0x020 from _ETW_REG_ENTRY
        $offset_ge1  = { 48 83 C0 20 }
        $offset_ge2  = { 48 83 C1 20 }

    condition:
        uint16(0) == 0x5A4D          // MZ header — PE file
        and filesize < 5MB

        and (
            // High confidence: explicit TI symbol or GUID present
            any of ($sym1, $sym2, $guid_str, $guid_bin)
        )
        and (
            // Must have a kernel primitive device path or IOCTL
            any of ($dev1, $dev2, $dev3, $dev4, $ioctl_gio, $ioctl_rtcore)
        )
        and (
            // Must enumerate kernel modules to resolve ntoskrnl base
            $ntqsi
        )
        and (
            // Structural confidence: offset arithmetic or zero-write pattern
            2 of ($kaslr_check, $zero_write1, $zero_write2,
                  $offset_pei1, $offset_pei2, $offset_pei3,
                  $offset_ge1, $offset_ge2)
        )
}

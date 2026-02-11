rule Suspicious_Native_Kernel_Driver_Loader
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects userland binaries attempting to load kernel drivers using NtLoadDriver and related techniques"
        date = "2026-02-11"
        version = "1.0"
        technique = "Userland Native API Driver Loading"
        category = "Defense Evasion / Privilege Abuse"
        reference = "Detection of embedded or dropped kernel driver loaders"

    strings:

        /* Native API usage */
        $ntload      = "NtLoadDriver" ascii wide
        $ntunload    = "NtUnloadDriver" ascii wide
        $rtlinit     = "RtlInitUnicodeString" ascii wide

        /* Privilege manipulation */
        $seload      = "SeLoadDriverPrivilege" ascii wide
        $adjusttok   = "AdjustTokenPrivileges" ascii wide
        $lookupluid  = "LookupPrivilegeValue" ascii wide

        /* Registry path for driver services */
        $regpath1    = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ascii wide
        $regpath2    = "SYSTEM\\CurrentControlSet\\Services\\" ascii wide

        /* Service / SCM interaction */
        $svc_kernel  = "SERVICE_KERNEL_DRIVER" ascii wide
        $createsvc   = "CreateServiceA" ascii wide
        $createsvcW  = "CreateServiceW" ascii wide
        $openscm     = "OpenSCManager" ascii wide

        /* Driver dropping behavior */
        $createfile  = "CreateFileA" ascii wide
        $createfileW = "CreateFileW" ascii wide
        $writefile   = "WriteFile" ascii wide
        $sys_ext     = ".sys" ascii wide

    condition:

        uint16(0) == 0x5A4D and  /* PE file */

        (
            /* Native API driver load + privilege manipulation */
            (
                $ntload and
                $seload and
                1 of ($adjusttok, $lookupluid)
            )
            or

            /* Native API load + registry service manipulation */
            (
                $ntload and
                1 of ($regpath*)
            )
            or

            /* SCM kernel service creation + driver dropping */
            (
                1 of ($createsvc, $createsvcW) and
                $svc_kernel and
                $sys_ext
            )
        )
}

rule Named_Pipe_Command_Execution_Technique
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects binaries that use Windows named pipes to send/receive commands and execute them (generic detection of technique)"
        date = "2025-10-23"
        reference = "Generic detection for named-pipe based command execution / IPC C2 / lateral movement"

    strings:
        // Windows named-pipe / pipe API (ASCII and wide)
        $s_CreateNamedPipeA      = "CreateNamedPipeA" wide ascii
        $s_CreateNamedPipeW      = "CreateNamedPipeW" wide ascii
        $s_CreateFileA           = "CreateFileA" wide ascii
        $s_CreateFileW           = "CreateFileW" wide ascii
        $s_ConnectNamedPipe      = "ConnectNamedPipe" wide ascii
        $s_ReadFile              = "ReadFile" wide ascii
        $s_WriteFile             = "WriteFile" wide ascii

        // Security / permission related APIs often used to allow remote access
        $s_InitSD                = "InitializeSecurityDescriptor" wide ascii
        $s_SetDacl               = "SetSecurityDescriptorDacl" wide ascii

        // Execution APIs / C runtime execution patterns
        $s_system_call           = "system(" ascii nocase
        $s_CreateProcessA        = "CreateProcessA" wide ascii
        $s_CreateProcessW        = "CreateProcessW" wide ascii
        $s_ShellExecuteA         = "ShellExecuteA" wide ascii
        $s_ShellExecuteW         = "ShellExecuteW" wide ascii

        // Common pipe path patterns (ASCII regex; matches \\.\pipe\<name> and UNC \\<ip>\pipe\<name>)
        $r_pipe_path             = /\\\\(?:\.|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[A-Za-z0-9\-\_\.]+)\\pipe\\[A-Za-z0-9\-\_\.]+/ ascii

        // Simple keywords also useful
        $s_dot_pipe              = "\\\\.\\pipe\\" ascii nocase
        $s_ip_pipe               = "\\\\127.0.0.1\\pipe\\" ascii nocase

    condition:
        // Require at least one pipe API + (either a pipe path/keyword OR an execution API)
        (1 of ($s_CreateNamedPipeA, $s_CreateNamedPipeW, $s_CreateFileA, $s_CreateFileW,
              $s_ConnectNamedPipe, $s_ReadFile, $s_WriteFile))
        and
        (
            any of ($r_pipe_path, $s_dot_pipe, $s_ip_pipe)
            or
            1 of ($s_system_call, $s_CreateProcessA, $s_CreateProcessW, $s_ShellExecuteA, $s_ShellExecuteW)
        )
}

rule Windows_NamedPipe_Interactive_Shell
{
    meta:
        description = "Detects Windows Named Pipe interactive shell implementations used for IPC-based command execution"
        author = "0x12 Dark Development"
        date = "2025-10-29"
        version = "1.0"
        severity = "high"
        reference = "Named Pipes as alternative C2 channel"
        mitre_attack = "T1055.001, T1570"
        
    strings:
        // Named Pipe creation patterns
        $pipe_create1 = "CreateNamedPipe" ascii wide
        $pipe_create2 = "\\\\.\\pipe\\" ascii wide
        $pipe_create3 = "\\\\pipe\\" ascii wide nocase
        
        // Named Pipe connection patterns
        $pipe_connect1 = "ConnectNamedPipe" ascii wide
        $pipe_connect2 = "CreateFile" ascii wide
        $pipe_connect3 = "WaitNamedPipe" ascii wide
        
        // Pipe I/O operations
        $pipe_io1 = "ReadFile" ascii wide
        $pipe_io2 = "WriteFile" ascii wide
        $pipe_io3 = "PeekNamedPipe" ascii wide
        $pipe_io4 = "TransactNamedPipe" ascii wide
        
        // Command execution indicators
        $cmd_exec1 = "_popen" ascii wide
        $cmd_exec2 = "CreateProcess" ascii wide
        $cmd_exec3 = "ShellExecute" ascii wide
        $cmd_exec4 = "WinExec" ascii wide
        $cmd_exec5 = "system(" ascii wide
        $cmd_exec6 = "cmd.exe" ascii wide nocase
        $cmd_exec7 = "powershell" ascii wide nocase
        
        // Pipe access modes suggesting bidirectional communication
        $duplex1 = "PIPE_ACCESS_DUPLEX" ascii wide
        $duplex2 = "GENERIC_READ" ascii wide
        $duplex3 = "GENERIC_WRITE" ascii wide
        
        // Threading for async operations (common in shells)
        $thread1 = "CreateThread" ascii wide
        $thread2 = "std::thread" ascii wide
        $thread3 = "_beginthread" ascii wide
        
        // Output capture patterns
        $capture1 = "fgets" ascii wide
        $capture2 = "ReadConsoleOutput" ascii wide
        $capture3 = "GetStdHandle" ascii wide
        
        // Pipe configuration suggesting shell behavior
        $config1 = "PIPE_READMODE_BYTE" ascii wide
        $config2 = "PIPE_READMODE_MESSAGE" ascii wide
        $config3 = "SetNamedPipeHandleState" ascii wide
        $config4 = "PIPE_WAIT" ascii wide
        $config5 = "PIPE_NOWAIT" ascii wide
        
        // Suspicious string patterns
        $str1 = "shell>" ascii wide
        $str2 = "cmd>" ascii wide
        $str3 = "execute command" ascii wide nocase
        $str4 = "exec>" ascii wide
        $str5 = "command output" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 5MB and
        (
            // Pattern 1: Named Pipe creation + command execution + bidirectional I/O
            (
                ($pipe_create1 or $pipe_create2) and
                any of ($cmd_exec*) and
                #pipe_io1 >= 2 and #pipe_io2 >= 2 and
                ($duplex1 or ($duplex2 and $duplex3))
            )
            or
            // Pattern 2: Named Pipe connection + command execution + async operations
            (
                ($pipe_connect1 or $pipe_connect2) and
                $pipe_connect3 and
                any of ($cmd_exec*) and
                any of ($thread*) and
                ($pipe_io1 and $pipe_io2)
            )
            or
            // Pattern 3: Comprehensive pipe shell indicators
            (
                any of ($pipe_create*) and
                any of ($pipe_connect*) and
                #pipe_io3 >= 1 and  // PeekNamedPipe is key for polling
                any of ($cmd_exec*) and
                any of ($capture*) and
                any of ($config*)
            )
            or
            // Pattern 4: High confidence based on multiple suspicious indicators
            (
                2 of ($pipe_create*) and
                3 of ($pipe_io*) and
                2 of ($cmd_exec*) and
                any of ($thread*) and
                any of ($str*)
            )
        )
}

rule Windows_NamedPipe_RemoteShell_Network
{
    meta:
        description = "Detects Named Pipe shells with remote/network capabilities (SMB-based C2)"
        author = "0x12 Dark Development"
        date = "2025-10-29"
        version = "1.0"
        severity = "critical"
        reference = "Named Pipes over SMB for lateral movement"
        mitre_attack = "T1021.002, T1570"
        
    strings:
        // Remote pipe patterns
        $remote_pipe1 = "\\\\\\\\%s\\\\pipe\\\\" ascii wide
        $remote_pipe2 = "\\\\\\\\.\\\\pipe\\\\" ascii wide
        $remote_pipe3 = "\\\\127.0.0.1\\pipe\\" ascii wide
        $remote_pipe4 = "\\\\localhost\\pipe\\" ascii wide
        
        // Network/SMB related
        $net1 = "WNetAddConnection" ascii wide
        $net2 = "NetUseAdd" ascii wide
        $net3 = "ImpersonateNamedPipeClient" ascii wide
        
        // Credential/authentication
        $auth1 = "LogonUser" ascii wide
        $auth2 = "LsaLogonUser" ascii wide
        
        // Pipe APIs
        $pipe1 = "CallNamedPipe" ascii wide
        $pipe2 = "CreateNamedPipe" ascii wide
        $pipe3 = "ConnectNamedPipe" ascii wide
        
        // Command execution
        $exec1 = "_popen" ascii wide
        $exec2 = "CreateProcess" ascii wide
        $exec3 = "ShellExecute" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            // Remote pipe + command execution
            (
                any of ($remote_pipe*) and
                any of ($exec*) and
                2 of ($pipe*)
            )
            or
            // Network connection + pipe + execution
            (
                any of ($net*) and
                any of ($pipe*) and
                any of ($exec*)
            )
            or
            // Authentication + pipe impersonation (privilege escalation)
            (
                any of ($auth*) and
                $net3 and
                any of ($pipe*)
            )
        )
}

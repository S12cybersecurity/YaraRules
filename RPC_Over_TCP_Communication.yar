rule RPC_Over_TCP_Communication : network rpc suspicious
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects Windows RPC over TCP/IP communication techniques commonly used for remote command execution and lateral movement"
        date = "2026-01-15"
        reference = "Custom RPC over TCP implementation pattern"
        severity = "medium"
        category = "network_communication"
        
    strings:
        // RPC protocol sequences for TCP/IP
        $proto_tcp1 = "ncacn_ip_tcp" ascii wide
        $proto_tcp2 = "ncacn_http" ascii wide
        
        // RPC server functions
        $rpc_server1 = "RpcServerUseProtseqEp" ascii
        $rpc_server2 = "RpcServerRegisterIf" ascii
        $rpc_server3 = "RpcServerListen" ascii
        $rpc_server4 = "RpcServerRegisterAuthInfo" ascii
        $rpc_server5 = "RpcServerUseProtseqEpA" ascii
        $rpc_server6 = "RpcServerUseProtseqEpW" ascii
        $rpc_server7 = "RpcServerRegisterIf2" ascii
        
        // RPC client functions
        $rpc_client1 = "RpcStringBindingCompose" ascii
        $rpc_client2 = "RpcBindingFromStringBinding" ascii
        $rpc_client3 = "RpcBindingSetAuthInfo" ascii
        $rpc_client4 = "RpcBindingFree" ascii
        
        // MIDL memory allocation functions (custom RPC implementations)
        $midl1 = "midl_user_allocate" ascii
        $midl2 = "midl_user_free" ascii
        $midl3 = "MIDL_user_allocate" ascii
        $midl4 = "MIDL_user_free" ascii
        
        // RPC exception handling
        $except1 = "RpcExceptionCode" ascii
        $except2 = "RpcTryExcept" ascii
        $except3 = "RpcEndExcept" ascii
        
        // Authentication constants/patterns
        $auth1 = "RPC_C_AUTHN_NONE" ascii
        $auth2 = "RPC_C_AUTHN_LEVEL_NONE" ascii
        $auth3 = "RPC_C_AUTHN_WINNT" ascii
        $auth4 = "RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH" ascii
        
        // Library imports
        $lib = "Rpcrt4.lib" ascii wide nocase
        $dll = "Rpcrt4.dll" ascii wide nocase
        
        // Common port patterns in RPC bindings (looking for custom ports)
        $port_pattern = /["']\d{4,5}["']/ ascii wide
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        filesize < 5MB and
        (
            // Server-side RPC implementation
            (
                $proto_tcp1 and
                2 of ($rpc_server*) and
                1 of ($midl*)
            )
            or
            // Client-side RPC implementation
            (
                $proto_tcp1 and
                2 of ($rpc_client*) and
                1 of ($midl*)
            )
            or
            // Suspicious combination: RPC + authentication manipulation
            (
                1 of ($proto_tcp*) and
                1 of ($auth*) and
                2 of ($rpc_server*, $rpc_client*) and
                ($lib or $dll)
            )
            or
            // High confidence: multiple RPC components with custom port
            (
                $proto_tcp1 and
                $port_pattern and
                1 of ($rpc_server*) and
                1 of ($rpc_client*) and
                1 of ($except*)
            )
        )
}

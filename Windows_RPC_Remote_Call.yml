rule Windows_RPC_Remote_Call
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects Windows RPC local client/server communication using ncalrpc or similar endpoints"
        date = "2026-01-14"
        version = "1.0"
        technique = "Local RPC client-server calls using RpcServerListen / RpcSendMessage"

    strings:
        // Common RPC server APIs
        $server1 = "RpcServerRegisterIf" ascii
        $server2 = "RpcServerListen" ascii
        $server3 = "RpcServerUseProtseqEp" ascii

        // Common RPC client APIs
        $client1 = "RpcStringBindingCompose" ascii
        $client2 = "RpcBindingFromStringBinding" ascii
        $client3 = "RpcSendMessage" ascii

        // Optional: memory allocation functions required by RPC stubs
        $alloc1 = "midl_user_allocate" ascii
        $alloc2 = "MIDL_user_allocate" ascii

    condition:
        // Detect binaries that either implement an RPC server or act as a client
        (any of ($server*) and any of ($alloc*)) or
        (any of ($client*) and any of ($alloc*))
}

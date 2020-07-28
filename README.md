tool to assist in development and testing of simple x86 network based buffer overflow exploits

use --help for instructions

default shellcode is an unstaged msfvenom generated payload for a bind shell on port 4444 (windowsx86)

NOTE: IF 0x00 IS A BAD CHAR, DO NOT USE the --SUB_ESP option with the EXPLOIT sub-command, INSTEAD USE NASM_SHELL AND DIRECTLY ADD YOUR STACK ADJUST TO THE SHELLCODE.BIN file

to be added: improve cli

to see real word useage examples, look in the notes.txt files in my tryharder repo


Examples:-

1) features
```
usage: bofman [-h] {test,exploit,q} ...

investigate and exploit buffer overflows

positional arguments:
  {test,exploit,q}  sub command help
    test            options for test
    exploit         options for exploit
    q               query for offsets

optional arguments:
  -h, --help        show this help message and exit
  ```
  
 2) test
 ```
 usage: bofman test [-h] [--len LEN] [--offset OFFSET] [--buffer-type {a,pattern,confirm,badchars}] [--command COMMAND] [-b B] [--post_command POST_COMMAND] [--stdout]      
                   ip port                                                                                                                                                  
                                                                                                                                                                            
positional arguments:                                                                                                                                                       
  ip                    ip of remote target                                                                                                                                 
  port                  remote port                                                                                                                                         

optional arguments:
  -h, --help            show this help message and exit
  --len LEN             size of buffer to send
  --offset OFFSET       offset to confirm
  --buffer-type {a,pattern,confirm,badchars}
                        type of buffer to send
  --command COMMAND     server command to prepend buffer with
  -b B                  badchars to exclude from buffer seperated by commas (in integer form)
  --post_command POST_COMMAND
                        server command to append buffer with (remember to escape backslashes)
  --stdout              send buffer to stdout instead of socket
```

3) exploit
```
usage: bofman exploit [-h] --len LEN --offsetEIP OFFSETEIP --eip EIP --shellcode SHELLCODE --shellcodeOffset SHELLCODEOFFSET [--sub_esp SUB_ESP] [--nops NOPS]
                      [--command COMMAND] [--post_command POST_COMMAND] [--stdout]
                      ip port

positional arguments:
  ip                    ip of remote target
  port                  remote port

optional arguments:
  -h, --help            show this help message and exit
  --len LEN             size of buffer to send
  --offsetEIP OFFSETEIP
                        how many bytes to write before EIP
  --eip EIP             memory location to overwrite EIP
  --shellcode SHELLCODE
                        path to shellcode in raw binary form
  --shellcodeOffset SHELLCODEOFFSET
                        offset to begin shellcode
  --sub_esp SUB_ESP     integer value to (1-9) of how many kilobytes to subtract from ESP
  --nops NOPS           number of nops to place before shellcode
  --command COMMAND     server command to prepend buffer with
  --post_command POST_COMMAND
                        server command to append buffer with (remember to escape backslashes)
  --stdout              send buffer to stdout instead of socke
  ```
  
  

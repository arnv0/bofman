tool to assist in development and testing of simple x86 network based buffer overflow exploits

use --help for instructions

default shellcode is an unstaged msfvenom generated payload for a bind shell on port 4444

to be implemented:
  bad char detection;
  stack adjust uses 0x00 i.e can't be used if 0x00 is a badchar, need to fix that too;

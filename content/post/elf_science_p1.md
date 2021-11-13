---
title: "ELF Science Part 1"
date: 2021-11-12T13:00:44-06:00
draft: true
---

One of the most difficult parts of creating offensive tools is preventing detection. Even if you employ the most advanced methodologies available, your tool will eventually be detected. At this point, the goal becomes making the analyst/reversers life as difficult as possible.

There are a number of ways of doing this, including breaking your payload up into smaller chunks to limit exposure and [loading functionality at runtime](https://x-c3ll.github.io/posts/fileless-memfd_create/). However, this post will focus on a different method. "Hardening" binary payloads. 

Binary hardening can involve a variety of techniques. For example, flexibility in binary formats allows for alterations that can confuse reversing tools. Another possible hardening procedure is **encryption**.

Encrypting our binary will make it far more difficult for an analyst to examine it, as they will no longer be able to use their tools to dissasemble it. However, this may also increase the chances of the payload being detected due to [entropy](https://www.cyberbit.com/blog/endpoint-security/malware-terms-code-entropy/).

An astute reader may immediately ask the question, "But if the binary is encrypted, how can it execute?". The short answer is: _it can't_. However, we can fix this by having the binary decrypt itself. This series of posts will focus on automating the ability to do just that, as well as potentially adding additional hardening techniques.

------

A possible way to do this would be to encrypt all functionality besides the entrypoint, then have the process decrypt it's other functions at the beginning of execution. Below is an example of how we could accomplish the encryption portion of this using Python:

```python
#!/usr/bin/env python3
import sys

def crypt(binary: str, start: int, stop: int):
    """Encrypts the provided binary from start address to stop address"""
    print(f"Encrypting {binary} from address {start} to address {stop}")
    size = stop - start                 #size of space to be encrypted
    with open(binary, 'rb+') as f:
        f.seek(start)                   #move file pointer to start address
        data = bytearray(f.read(size))  #read in data to be encrypted
        for i in range(len(data)):      #encrypt data using single byte xor
            data[i] = data[i] ^ 0xFA
        data = bytes(data)              #convert back to bytes for writing to binary

        f.seek(start)                   #return to start address
        f.write(data)                   #replace data with encrypted version


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: ./crypt [binary] [start address] [stop address]")
        sys.exit(1)

    binary = sys.argv[1]                #binary file name
    try:
        start = int(sys.argv[2])        #encryption start address
    except ValueError:
        start = int(sys.argv[2], 16)

    try:
        stop = int(sys.argv[3])         #encryption end address
    except ValueError:
        stop = int(sys.argv[3], 16)

    crypt(binary, start, stop)
```

The encryption script begins by retrieving the relevant values from the command line invocation. This includes the name of the binary to encrypt, the start address of encryption, and the end address of encryption. If any of these values are missing, we will print usage instructions and exit with a non-zero exit code to signify an error occurred. The start address and stop address will then be converted to integers. They can be provided in either base 10 or base 16 format, thanks to the added exception handling.

Now that we have our values, we can pass them to the encryption function (crypt). The encryption function calculates the length of data to encrypt. It then opens the binary to modify it appropriately. Once the binary is open, the file pointer is moved to the start address via seek() and then the data to encrypt is read in. We convert this data to a bytearray object, as bytes are immutable in python. Now that we have a byte array, we can modify it via our "encryption" method (single byte xor). We'll use a fixed key of 0xFA in this example.

Once encryption is complete, the modified data can be converted back into bytes and written back to the binary. 

------

Next we'll need a basic binary to demonstrate our encryption on:

```c
#include <stdio.h>

void encrypt_me(){
    puts("Sneaky function!");
}

int main()
{
    puts("Main function");
    encrypt_me();
}
```

Compilation and execution can be seen below:

![Compilation GIF](/images/basic-bin.gif)

Our compilation command:
```shell
gcc -g -no-pie -o main main.c
```
Uses the following flags
- **-g** to enable symbols
- **-no-pie** to disable position independence

Disabling position independence will greatly simplify the following steps (Handling [PIE](https://access.redhat.com/blogs/766093/posts/1975793) may be the subject of a later post).

------

Let's take a look at the dissasembly of the encrypt_me() function

```shell
rgood@debian:~/Playground/self-decrypt$ objdump -M intel -D main | grep "<encrypt_me>:" -A 7
0000000000401142 <encrypt_me>:
  401142:       55                      push   rbp
  401143:       48 89 e5                mov    rbp,rsp
  401146:       48 8d 3d b7 0e 00 00    lea    rdi,[rip+0xeb7]        # 402004 <_IO_stdin_used+0x4>
  40114d:       e8 ee fe ff ff          call   401040 <puts@plt>
  401152:       90                      nop
  401153:       5d                      pop    rbp
  401154:       c3                      ret
```

The function begins at addres 0x401142 in virtual memory. However, we want to encrypt the function while it resides on disk. This means that we'll need to determine the functions address within the binary.

We can accomplish this using the readelf utility:

```shell
rgood@debian:~/Playground/self-decrypt$ readelf -SW ./main | grep .text
  [13] .text             PROGBITS        0000000000401060 001060 0001c1 00  AX  0   0 16
```

We invoke readelf with the following flags:
- -S to read the Sections of the binary
- -W to output in wide format for readability

The .text section of a binary typically contains the executable code. We can see that the .text segment is mapped to address 0x401060 in virtual memory, which is associated with address 0x1060 in on the physical file. By association, we know that our function of interest resides from address 0x1142 to 0x1154 (basically just strip off the leading 40).

Let's verify this using hexedit. If you refer to the previous objdump output, you'll see our function begins with the following bytes: 55 48 89 e5. 

![hexedit GIF](/images/hexedit.gif)

Now that we've verified the address space of our function, let's encrypt it.

```shell
rgood@debian:~/Playground/self-decrypt$ ./encrypt.py main 0x1142 0x1154
Encrypting main from address 4418 to address 4436
```

Let's take another look at the function

```shell
rgood@debian:~/Playground/self-decrypt$ objdump -M intel -D main | grep "<encrypt_me>:" -A 7
0000000000401142 <encrypt_me>:
  401142:       af                      scas   eax,DWORD PTR es:[rdi]
  401143:       b2 73                   mov    dl,0x73
  401145:       1f                      (bad)  
  401146:       b2 77                   mov    dl,0x77
  401148:       c7                      (bad)  
  401149:       4d f4                   rex.WRB hlt 
  40114b:       fa                      cli
```

As expected, it is now unintelligible. If we attempt to execute the binary, it will segfault once it reaches the encrypted function.

![segfault GIF](/images/segfault1.gif)

-----

TODO: 
- Add decryption logic
- Show segfault due to protections
- Show protections in readelf
- Talk about read write execute segment being flaggable, so use mprotect instead.
- Demonstrate decryption working
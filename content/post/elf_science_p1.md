---
title: "ELF Science Part 1"
date: 2021-11-12T13:00:44-06:00
draft: true
---

## Introduction

One of the most difficult parts of creating offensive tools is preventing detection. Even if you employ the most advanced methodologies available, your tool will eventually be detected. At this point, the goal becomes making the analyst/reversers life as difficult as possible.

There are a number of ways of doing this, including breaking your payload up into smaller chunks to limit exposure and [loading functionality at runtime](https://x-c3ll.github.io/posts/fileless-memfd_create/). However, this post will focus on a different method. "Hardening" binary payloads. 

Binary hardening can involve a variety of techniques. For example, flexibility in binary formats allows for alterations that can confuse reversing tools. Another possible hardening procedure is **encryption**.

Encrypting our binary will make it far more difficult for an analyst to examine it, as they will no longer be able to use their tools to dissasemble it. However, this may also increase the chances of the payload being detected due to [entropy](https://www.cyberbit.com/blog/endpoint-security/malware-terms-code-entropy/).

An astute reader may immediately ask the question, "But if the binary is encrypted, how can it execute?". The short answer is: _it can't_. However, we can fix this by having the binary decrypt itself. This series of posts will focus on automating the ability to do just that, as well as potentially adding additional hardening techniques.

------

## Encryption

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

## Payload

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

## Analysis

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

## Decryption

Now we'll add our decryption logic:

```c
#include <stdio.h>
#include <stdint.h>

typedef int64_t address_t;

void encrypt_me(){
    puts("Sneaky function!");
}

int main()
{
    int retval = 0;

    puts("Main function");

    void *addr = encrypt_me; 
    address_t function_size = (address_t)main - (address_t)encrypt_me - 1; // Calculates distance between encrypt_me() and main()
    
    /* Decryption loop */
    while (function_size > 0)
    {
        *(int *)addr = *(int *)addr ^ 0xFA;
        addr += 1;
        function_size -= 1;
    }
    /* End Decryption loop */
    
    encrypt_me();
}
```

There's a lot going on here so let's break it down.

First of all we'll create a new type to represent addresses: **address_t**. This will be a 64 bit integer since we're dealing with x86-64 architecture.

```c
typedef int64_t address_t;
```

The next new addition is grabbing the address of the encrypt_me() function, and then calculating it's size.

```c
void *addr = encrypt_me; 
address_t function_size = (address_t)main - (address_t)encrypt_me - 1;
```

We're using a void* type for the address of encrypt_me here, as we want to increment it by one byte at a time. If we don't do this and instead use an adress_t here, when we try to increment the address (addr+=1), it will increment by 8 bytes. This is because the size of an address on this architecture is 8 bytes (64 bits).

The size of encrypt_me() can be calculated in this way, as we have seen in the objdump output that it resides after main() in memory. Therefore we can find the size of encrypt_me() by calculating the difference between the two, and subtract an additional byte to make the math line up with our encryption function.

Lastly, we have our decryption loop.

```c
while (function_size > 0)
{
    *(int *)addr = *(int *)addr ^ 0xFA;
    addr += 1;
    function_size -= 1;
}
```

This loop will iterate over each byte in the encrypt_me() function (addr += 1) as long as there are still bytes left to encrypt (function_size > 0).

At each iteration, it will decrypt (xor) the instruction residing at the current address (*(int *)addr) with our key (0xFA). We're converting to an (int *) here to allow for this arithmetic, and dereferencing the pointer to alter the actual instruction instead of the address the instruction resides at. We will then take the result and overwrite the formerly encrypted instruction byte.

You might need to read that last bit a couple of times for it to make sense...

Before we continue, we'll need to check where encrypt_me is living in memory now, as it has most likely moved.

```shell
rgood@debian:~/Playground/self-decrypt$ objdump -M intel -D main | grep "<encrypt_me>:" -A 18
0000000000401122 <encrypt_me>:
  401122:       55                      push   rbp
  401123:       48 89 e5                mov    rbp,rsp
  401126:       48 8d 3d d7 0e 00 00    lea    rdi,[rip+0xed7]        # 402004 <_IO_stdin_used+0x4>
  40112d:       e8 fe fe ff ff          call   401030 <puts@plt>
  401132:       90                      nop
  401133:       5d                      pop    rbp
  401134:       c3                      ret    

0000000000401135 <main>:
  401135:       55                      push   rbp
  401136:       48 89 e5                mov    rbp,rsp
  401139:       48 83 ec 20             sub    rsp,0x20
  40113d:       c7 45 ec 00 00 00 00    mov    DWORD PTR [rbp-0x14],0x0
  401144:       48 8d 3d ca 0e 00 00    lea    rdi,[rip+0xeca]        # 402015 <_IO_stdin_used+0x15>
  40114b:       e8 e0 fe ff ff          call   401030 <puts@plt>
  401150:       48 8d 05 cb ff ff ff    lea    rax,[rip+0xffffffffffffffcb]        # 401122 <encrypt_me>
  401157:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  40115b:       48 8d 05 d3 ff ff ff    lea    rax,[rip+0xffffffffffffffd3]        # 401135 <main>
```

Based on this, we know we'll need to provide a start address of 0x401122 and a stop address of 0x401134 to our encryption python script.

Alright, let's do this!

![Decryption Failure](/images/decrypt-fail.gif)

Oh no! It failed. Don't worry, we'll have that fixed up in no time.

-----

## Permissions

As mentioned previously, the code in a binary resides in the .text section, let's take another look at it...

```shell
rgood@debian:~/Playground/self-decrypt$ readelf -SW main | grep .text
[13] .text             PROGBITS        0000000000401040 001040 0001d1 00  AX  0   0 16
```

If you look near the end of the line, you'll see "AX". These letters represent the current permission flags of this section of the binary. This differs from something like the data section, which has permissions "WA".

```shell
[23] .data             PROGBITS        0000000000404020 003020 000010 00  WA  0   0  8
```

The big difference between the two, is that the .text section is executable (makes sense since this is where the code lives) but not writable, and the .data section is writable but not executable.

This is why we received a segfault when we attempted to write to the .text section in memory.

Both of these sections are loaded into something called a _segment_ once the binary is executing. Let's take a look at these segments.

```shell

Elf file type is EXEC (Executable file)
Entry point 0x401040
There are 11 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000400040 0x0000000000400040 0x000268 0x000268 R   0x8
  INTERP         0x0002a8 0x00000000004002a8 0x00000000004002a8 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000400000 0x0000000000400000 0x000438 0x000438 R   0x1000
  LOAD           0x001000 0x0000000000401000 0x0000000000401000 0x00021d 0x00021d R E 0x1000
  LOAD           0x002000 0x0000000000402000 0x0000000000402000 0x000188 0x000188 R   0x1000
  LOAD           0x002e10 0x0000000000403e10 0x0000000000403e10 0x000220 0x000228 RW  0x1000
  DYNAMIC        0x002e20 0x0000000000403e20 0x0000000000403e20 0x0001d0 0x0001d0 RW  0x8
  NOTE           0x0002c4 0x00000000004002c4 0x00000000004002c4 0x000044 0x000044 R   0x4
  GNU_EH_FRAME   0x002024 0x0000000000402024 0x0000000000402024 0x000044 0x000044 R   0x4
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x002e10 0x0000000000403e10 0x0000000000403e10 0x0001f0 0x0001f0 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame 
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss 
   06     .dynamic 
   07     .note.ABI-tag .note.gnu.build-id 
   08     .eh_frame_hdr 
   09     
   10     .init_array .fini_array .dynamic .got
```

Reading this output, we can see from the Section to Segment mapping that the .text section maps to segment 3, shown below:

```shell
LOAD           0x001000 0x0000000000401000 0x0000000000401000 0x00021d 0x00021d R E 0x1000
```

As expected, this segment has Read and Execute permissions, but no write permissions. Can you see where the .data section is mapped to and the relevant segments permissions?

We could modify the binary to make the .text section and segment 03 writable, but many defensive tools [signaturize](https://blog.malwarebytes.com/glossary/signature/#:~:text=In%20computer%20security%2C%20a%20signature,used%20by%20families%20of%20malware.) this kind of behavior.

Instead, we'll use the mprotect function to change the permissions in memory at execution time.

-----

## Final

Here's the new version of our self-modifying program:

```c
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>

typedef int64_t address_t;

void encrypt_me(){
    puts("Sneaky function!");
}

int main()
{
    int retval = 0;

    puts("Main function");
    retval = mprotect((int *)0x401000, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (retval < 0)
        return errno;

    void *addr = encrypt_me;

    address_t function_size = (address_t)main - (address_t)encrypt_me - 1;
    while (function_size > 0)
    {
        *(int *)addr = *(int *)addr ^ 0xFA;
        addr+=1;
        function_size -= 1;
    }
    
    encrypt_me();
}
```

The main addition here is the mprotect call
```c
retval = mprotect((int *)0x401000, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
```

We're passing in our page aligned memory space (0x401000) and the amount of memory to modify (4096 bytes). These values must both be [page-aligned](https://scoutapm.com/blog/understanding-page-faults-and-memory-swap-in-outs-when-should-you-worry#:~:text=Linux%20allocates%20memory%20to%20processes,represent%204KB%20of%20physical%20memory.). We're then changing the permissions of that memory to allow for read, write, and exec. This will allow us to modify the code, and still execute it once modification is complete.

A more robust way to implement the alignment is shown below:

```c
address_t page_aligned_addr = (address_t)encrypt_me & 0xFFF000;
```

Which results in the following final version of our code:

```c
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>

typedef int64_t address_t;

void encrypt_me(){
    puts("Sneaky function!");
}

int main()
{
    int retval = 0;

    puts("Main function");
    address_t page_aligned_addr = (address_t)encrypt_me & 0xFFF000;
    retval = mprotect((void *)page_aligned_addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (retval < 0)
        return errno;

    void *addr = encrypt_me;

    address_t function_size = (address_t)main - (address_t)encrypt_me - 1;
    while (function_size > 0)
    {
        *(int *)addr = *(int *)addr ^ 0xFA;
        addr+=1;
        function_size -= 1;
    }
    
    encrypt_me();
}
```

Let's give this another shot. First we'll compile.

```shell
rgood@debian:~/Playground/self-decrypt$ gcc -g -no-pie -o main main.c
```

Then we'll check our addresses.

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

And finally, we'll encrypt and run.

![Decrypt Success](/images/decrypt-success.gif)

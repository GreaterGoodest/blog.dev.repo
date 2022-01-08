---
title: "ELF Science Part 3"
date: 2022-01-07T20:57:52-06:00
draft: false
---

## Introduction

This post is part of a three part series (so far) 
- [Part 1](/post/elf_science_p1/)
- [Part 2](/post/elf_science_p2/)

As usual, a regularly updated version of the code base associated with this series can be found on my [github](https://github.com/GreaterGoodest/elf-magic).

In the last edition of ELF Science, we defeated our encryption methodology by running the binary in a debugger, setting a breakpoint after self-decryption is complete, and dumping the decrypted memory. We then re-wrote the binary using these decrypted instructions, and NOP'd out the xor encryption method.

In this edition, we'll return to our scheming ways and discuss additional ways to frustrate would be reversers. 

Firstly, we'll check to see if we're are being run in a debugger. If that's the case, we'll immediately exit. After that, we'll check if we are running in a virtualized environment (VMware, etc.). Virtualized environments are commonly used to detonate malware, as they reduce the risk to the host system. Of course, you wouldn't want to perform this check if you're attacking an EC2 instance or something similar. If we detect that the host system is virtualized, this will also lead to early termination. Quite devious.

Of course, once we've implemented these new features we will also explore how easily they can be defeated. 

## Detecting Debugger

One neat thing we can do during execution is access our own process information located within /proc/self/status. This file can give us useful information such as our Pid and Parent Pid. We can also use the TracerPid value to determine if something is attempting to debug us. 

For example, let's look at the status file of a random process (chrome-sandbox):

```shell
rgood@debian:~/Projects/blog.dev.repo$ sudo cat /proc/43338/status                                                    
Name:   chrome-sandbox                                                                                                
Umask:  0022                                                                                                          
State:  S (sleeping)                                                                                                  
Tgid:   43338                                                                                                         
Ngid:   0                                                                                                             
Pid:    43338                                                                                                         
PPid:   43323                                                                                                         
TracerPid:      0
```

Here we can see that the TracerPid is 0, as there is no debugger attached to the process. Now let's take a look a process i've attached gdb to:

```shell
rgood@debian:~/Projects/blog.dev.repo$ sudo cat /proc/43312/status                                                    
Name:   a.out                                                                                                         
Umask:  0022                                                                                                          
State:  t (tracing stop)                                                                                              
Tgid:   43312                                                                                                         
Ngid:   0                                                                                                             
Pid:    43312                                                                                                         
PPid:   43309                                                                                                         
TracerPid:      43309
```

Here we can see that the TracerPid has a non-zero value. If we take a look at this pid, we can see that it's our gdb process pid:

```shell
rgood@debian:~/Projects/blog.dev.repo$ sudo cat /proc/43309/status                                                    
Name:   gdb
```

Using this knowledge, we will add a check into our binary to determine if a debugger has attached to us.

```c
uint32_t check_tracer(){
    int32_t retval = 0;
    int32_t fd = 0;

    fd = open("/proc/self/status", O_RDONLY);
    if(fd == -1)
    {
        perror("open /proc/self/status");
        return errno;
    }

    // Read our process information into memory
    char buff[1028];
    retval = read(fd, buff, sizeof(buff));
    if (retval == -1)
    {
        perror("read /proc/self/status");
        return errno;
    }

    // Iterate until TracerPid line found
    char *line = NULL;
    const char *key = "TracerPid";
    line = strtok(buff, "\n");
    while (strncmp(line, key, sizeof(key)))
    {
        line = strtok(NULL, "\n");
    }

    // Get TracerPid value from line
    char *pid_str = NULL;
    pid_str = strtok(line, ":");
    pid_str = strtok(NULL, "");
    int pid = strtol(pid_str, NULL, 10);

    // Check if debugger is attached
    if (pid != 0)
    {
        puts("Spy Discovered!");
        exit(0);
    }

    return 0;
}

int main()
{
    int retval = check_tracer();    
    if (retval != 0)
    {
        puts("check tracer failed");
        return retval;
    }
    puts("No Spy Found...");
}
```

Let's see what happens now when we run the binary normally, and when we run it using the debugger.

![Catch Debugger](/images/Catch-Debug.gif)

As you can see, when we run the binary normally we see the "No Spy Found..." message, but when it is executed using GDB, we see "Spy Discovered...". This demonstrates that we can detect dynamic analysis attempts.

## Detecting Virtualization

Next we are going to attempt to detect if we are running in a virtualized machine. This is useful as malware analysis often takes place in a VM, and we can theoretically force a reverser to use bare metal, or some other clever techniques. 

The method we'll use here only works on x86 architecture machines, and even then isn't 100% reliable. But it appears to work often enough to be worth implementing.

We can learn more about the system we are running on by looking at /proc/cpuinfo. This contains information on the system CPU, including a variety of informational flags. One of these flags is "hypervisor". If this flag is present, then we are running on a virtualized instance.

Let's add in another check to our binary to determine if this flag is present.

```c
int32_t virtualization_check()
{
    int32_t retval = 0;
    int32_t fd = 0;

    //open cpuinfo file for analysis
    fd = open("/proc/cpuinfo", O_RDONLY);
    if(fd == -1)
    {
        perror("open /proc/cpuinfo");
        return errno;
    }

    // read in contents of /proc/cpuinfo
    char buff[1028];
    retval = read(fd, buff, sizeof(buff));
    if (retval == -1)
    {
        perror("read /proc/cpuinfo");
        return errno;
    }    

    // check if hypervisor flag is set
    const char *hyper_string = "hypervisor";    
    if (strstr(buff, hyper_string))
    {
        puts("We're virtualized!");
        exit(0);
    }
    return 0;
}
```

It goes without saying that you would not want to implement this technique if the target was a virtualized machine, such as an EC2 instance. I suppose a positive side effect of running your infrastructure in the cloud is you don't have to worry about malware that does this kind of check.

Here's our final program:

```c
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

uint32_t check_tracer(){
    int32_t retval = 0;
    int32_t fd = 0;

    fd = open("/proc/self/status", O_RDONLY);
    if(fd == -1)
    {
        perror("open /proc/self/status");
        return errno;
    }

    char buff[1028];
    retval = read(fd, buff, sizeof(buff));
    if (retval == -1)
    {
        perror("read /proc/self/status");
        return errno;
    }

    char *line = NULL;
    const char *key = "TracerPid";
    line = strtok(buff, "\n");
    while (strncmp(line, key, sizeof(key)))
    {
        line = strtok(NULL, "\n");
    }

    char *pid_str = NULL;
    pid_str = strtok(line, ":");
    pid_str = strtok(NULL, "");

    int pid = strtol(pid_str, NULL, 10);

    if (pid != 0)
    {
        puts("Spy Discovered!");
        exit(0);
    }

    return 0;
}

int32_t virtualization_check()
{
    int32_t retval = 0;
    int32_t fd = 0;

    fd = open("/proc/cpuinfo", O_RDONLY);
    if(fd == -1)
    {
        perror("open /proc/cpuinfo");
        return errno;
    }

    char buff[1028];
    retval = read(fd, buff, sizeof(buff));
    if (retval == -1)
    {
        perror("read /proc/cpuinfo");
        return errno;
    }    

    const char *hyper_string = "hypervisor";    
    if (strstr(buff, hyper_string))
    {
        puts("We're virtualized!");
        exit(0);
    }
    return 0;
}

int main()
{
    int retval = check_tracer();    
    if (retval != 0)
    {
        puts("check tracer failed");
        return retval;
    }

    retval = virtualization_check();
    if (retval != 0)
    {
        puts("virtualization check failed");
        return retval;
    }

    puts("No Spy Found...");
}
```

## Anti-Anti-RE

This implementation is fairly trivial, and real world samples will make it much more difficult to determine that they are even doing these checks.

To defeat this exmample, we'll just add in a relative jump.

By looking at the dissasembly, we can see the distance we need to jump.

```shell
00000000000013e6 <main>:                                                                                              
    13e6:       55                      push   rbp                                                                    
    13e7:       48 89 e5                mov    rbp,rsp                                                                
    13ea:       48 83 ec 10             sub    rsp,0x10                                                               
    13ee:       b8 00 00 00 00          mov    eax,0x0                                                                
    13f3:       e8 cd fd ff ff          call   11c5 <check_tracer>                                                    
    13f8:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax                                                
    13fb:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0                                                
    13ff:       74 11                   je     1412 <main+0x2c>                                                       
    1401:       48 8d 3d ad 0c 00 00    lea    rdi,[rip+0xcad]        # 20b5 <_IO_stdin_used+0xb5>                    
    1408:       e8 43 fc ff ff          call   1050 <puts@plt>                                                        
    140d:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]                                                
    1410:       eb 35                   jmp    1447 <main+0x61>                                                       
    1412:       b8 00 00 00 00          mov    eax,0x0                                                                
    1417:       e8 03 ff ff ff          call   131f <virtualization_check>                                            
    141c:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax                                                
    141f:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0                                                
    1423:       74 11                   je     1436 <main+0x50>                                                       
    1425:       48 8d 3d 9d 0c 00 00    lea    rdi,[rip+0xc9d]        # 20c9 <_IO_stdin_used+0xc9>                    
    142c:       e8 1f fc ff ff          call   1050 <puts@plt>                                                        
    1431:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]                                                
    1434:       eb 11                   jmp    1447 <main+0x61>                                                       
    1436:       48 8d 3d a8 0c 00 00    lea    rdi,[rip+0xca8]        # 20e5 <_IO_stdin_used+0xe5>                   
    143d:       e8 0e fc ff ff          call   1050 <puts@plt>                                                       
    1442:       b8 00 00 00 00          mov    eax,0x0
    1447:       c9                      leave
    1448:       c3                      ret
    1449:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
```

We'll be jumping from the mov eax instruction just prior to the check_tracer call (0x13ee) to the instruction that loads the final string for printing (0x1436). That means we need to jump (0x1436 - 0x13ee = 0x48) bytes. We'll subtract another two bytes for our jmp instruction length, resulting in a 0x46 byte jump. We'll accomplish this using hexedit as shown in the previous posts, adding in our 0xeb 0x46 instructions (relative jump 46 bytes). This results in our main function looking like this (note the jmp at 0x13ee):

```shell
00000000000013e6 <main>:                                                                                              
    13e6:       55                      push   rbp                                                                    
    13e7:       48 89 e5                mov    rbp,rsp                                                                
    13ea:       48 83 ec 10             sub    rsp,0x10                                                               
    13ee:       eb 47                   jmp    1437 <main+0x51>                                                       
    13f0:       00 00                   add    BYTE PTR [rax],al                                                      
    13f2:       00 e8                   add    al,ch                                                                  
    13f4:       cd fd                   int    0xfd                                                                   
    13f6:       ff                      (bad)                                                                         
    13f7:       ff 89 45 fc 83 7d       dec    DWORD PTR [rcx+0x7d83fc45]                                             
    13fd:       fc                      cld                                                                           
    13fe:       00 74 11 48             add    BYTE PTR [rcx+rdx*1+0x48],dh                                           
    1402:       8d 3d ad 0c 00 00       lea    edi,[rip+0xcad]        # 20b5 <_IO_stdin_used+0xb5>                    
    1408:       e8 43 fc ff ff          call   1050 <puts@plt>                                                        
    140d:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]                                                
    1410:       eb 35                   jmp    1447 <main+0x61>                                                       
    1412:       b8 00 00 00 00          mov    eax,0x0                                                                
    1417:       e8 03 ff ff ff          call   131f <virtualization_check>                                            
    141c:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax                                                
    141f:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0                                                
    1423:       74 11                   je     1436 <main+0x50>                                                       
    1425:       48 8d 3d 9d 0c 00 00    lea    rdi,[rip+0xc9d]        # 20c9 <_IO_stdin_used+0xc9>                    
    142c:       e8 1f fc ff ff          call   1050 <puts@plt>                                                        
    1431:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]                                                
    1434:       eb 11                   jmp    1447 <main+0x61>                                                       
    1436:       48 8d 3d a8 0c 00 00    lea    rdi,[rip+0xca8]        # 20e5 <_IO_stdin_used+0xe5>                    
    143d:       e8 0e fc ff ff          call   1050 <puts@plt>                                                        
    1442:       b8 00 00 00 00          mov    eax,0x0                                                                
    1447:       c9                      leave
    1448:       c3                      ret
    1449:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0] 
```

I'm not sure why the relative jump ended up being interpreted as 47 bytes, but we can now execute the sample without triggering any of its detection methods.

## Conclusion

The methodologies shown here are a highly simplified version of real world techniques, that are still useful to showcase what is possible in the realm of anti-RE. Feel free to contact me with any suggestions and/or corrections. Thanks for reading!
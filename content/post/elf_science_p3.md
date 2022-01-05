---
title: "ELF Science Part 3"
date: 2021-12-17T14:57:52-06:00
draft: true
---

## Introduction

This post is part of a three part series (so far) 
- [Part 1](/post/elf_science_p1/)
- [Part 2](/post/elf_science_p2/)

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


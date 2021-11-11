---
title: "THICCelf Part 1: Background"
date: 2021-11-11T13:00:44-06:00
draft: true
---

One of the most difficult parts of creating offensive tools is preventing detection. Even if you employ the most advanced methodologies available, your tool will eventually be detected. At this point, the goal becomes making the analyst/reversers life as difficult as possible.

There are a number of ways of doing this, including breaking your payload up into smaller chunks to limit exposure and [loading functionality at runtime](https://x-c3ll.github.io/posts/fileless-memfd_create/). However, this post will focus on a different method. "Hardening" binary payloads. 

There of a number of ways to harden a payload. For example, flexibility in binary formats allows for alterations that can confuse reversing tools. Another possible hardening procedure is **encryption**.

Encrypting our binary will make it far more difficult for an analyst to examine it, as they will no longer be able to use their tools to dissaseemble it. However, this may also increase the chances of the payload being detected due to [entropy](https://www.cyberbit.com/blog/endpoint-security/malware-terms-code-entropy/).

An astute reader may immediately ask the question, "But if the binary is encrypted, how can it execute?". The short answer is: _it can't_. However, we can fix this by having the binary decrypt itself. This series of posts, and the tool developed as a result, will focus on automating the ability to do just that.

------

A possible way to do this would be to encrypt all functionality besides the entrypoint, then have the process decrypt it's other functions at the beginning of execution. 
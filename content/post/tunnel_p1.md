---
title: "Sneaky Packets Part 1 - Basic Proxy/Tunnel"
date: 2022-05-08T17:49:54-05:00
draft: true
---

## Introduction

Don't you hate it when pesky firewall rules or network configurations prevent you from reaching your favorite malicious domains? I know it's an every day frustration for most folks when their implants can't properly reach back to their C2. Let's dive into some things we can do to alleviate some common networking challenges faced by red teams, as well as inform blue teamers of some typical shenanigans used to circumvent various network protections.  

Now you might be wondering why we would want to build our own proxy and/or tunneling capability when there's lots of great open source tools already available. We could use NGINX to proxy our traffic, or SSH to create any tunnels we might need. 

<div style="text-align:center;">
    <img alt="Roll Your Own" src="/images/rollurown.PNG" height=300 />
</div>

Well those solutions are boring, and we're not skids so we want to understand how this kind of stuff works under the hood. Knowing how to implement these types of features also allows you to add them into all sorts of useful tools, as well as understanding how adversaries might be using them in their capabilities.

![Tunnel to Private Web](/images/tunnel-to-priv-web.gif)
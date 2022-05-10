---
title: "Sneaky Packets Part 1 - Basic Proxy/Tunnel"
date: 2022-05-08T17:49:54-05:00
draft: false 
---

## Introduction

The repo associated with this project can be found [here](https://github.com/GreaterGoodest/tunnel).

Don't you hate it when pesky firewall rules or network configurations prevent you from reaching your favorite malicious domains? I know it's an every day frustration for most folks when their implants can't properly reach back to their Command and Control (C2). Let's dive into some things we can do to alleviate common networking challenges faced by red teams, as well as inform blue teamers of typical shenanigans used to circumvent various network protections.  

Now you might be wondering why we would want to build our own proxy and/or tunneling capability when there's lots of great open source tools already available. We could use [NGINX](https://www.nginx.com/) to proxy our traffic, or [SSH](https://en.wikipedia.org/wiki/Secure_Shell) to create any tunnels we might need. 

<div style="text-align:center;">
    <img alt="Roll Your Own" src="/images/rollurown.PNG" height=300 />
</div>

Well those solutions are boring, and we're not skids so we want to understand how this kind of stuff works under the hood. Knowing how to implement these types of features also allows you to add them into all sorts of useful tools, as well as understanding how adversaries might be using them in their capabilities. In addition, having unique tools can often reduce the chances of your methodologies/tools already being signaturized.

This tutorial will walk you through how to implement your own simple proxy and tunnelling capability. I've also put together a docker-based environment involving multiple containers to show you some typical use cases.

## Proxying

To build towards the concept of tunneling, we'll start by implementing a simple proxy. Proxies are fairly simple and most people are familiar with them, making them a great starting point. The proxy I'll be demonstrating in this tutorial is purposefully as simple as possible. For that reason it is not at all ready for any sort of deployment (don't use it). This also goes for the tunneling code shown later. Perhaps as we build on these techniques in future tutorials, we'll approach something remotely deployable. 

The concept of a proxy is straight forward enough. A proxy simply acts as a forwarding agent for any of your network traffic. In this case we'll be focusing on [TCP](https://www.fortinet.com/resources/cyberglossary/tcp-ip#:~:text=TCP%20stands%20for%20Transmission%20Control,data%20and%20messages%20over%20networks.) based communications, but similar methodologies would allow this to also be expanded to [UDP](https://www.techtarget.com/searchnetworking/definition/UDP-User-Datagram-Protocol#:~:text=User%20Datagram%20Protocol%20(UDP)%20is,provided%20by%20the%20receiving%20party.). In our example, we'll create a bare bones TCP traffic forwarder that will listen for connections on a specified port, and forward the received traffic to a specified destination.  

![Proxy](/images/proxy.gif)

Our main function will set up a local listener to receive any traffic that is to be forwarded. Upon receiving a connection, it will establish another connection to the specified final destination. At this point it will loop, transfering data back and forth from the original source to the final destination and vice versa. The proxy sits in the middle of these interactions, ensuring packets get where they are supposed to go, and somewhat masking the identity of the original source.

Here's the main function for our proxy, which we will break down momentarily:

```c
int main()
{
    int status = 0;
    int listen_sock = 0;  // Receives proxy requests
    int remote_sock = 0;  // Proxy target
    int client_sock = 0;  // Client to proxy
    struct sockaddr_in client_addr = {0};

    status = setup_local_listener(&listen_sock);
    if (status < 0)
    {
        puts("main: Failed to setup local listener.");
        return 1;
    }

    while(1){ 
        if (client_sock <= 0)
        {
            client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &(int){0});
            if (client_sock == -1)
            {
                if (errno != EAGAIN){
                    perror("main accept");
                    return errno;
                }
            } else 
            {
                puts("accepted");
                status = fcntl(client_sock, F_SETFL, fcntl(client_sock, F_GETFL, 0) | O_NONBLOCK);
                if (status == -1)
                {
                    perror("main client_sock fnctl");
                    return status;
                }
            }
        }else {
            if (!remote_sock){
                status = setup_remote_sock(&remote_sock);
                if (status != 0)
                {
                    puts("main: Failed to setup remote socket.");
                    return 1;
                }
            }
            status = data_checks(client_sock, remote_sock);
            if (status < 0 && errno != EAGAIN)
            {
                puts("main: Failed data checks.");
                return 1;
            }else if (status == 0){
                puts("connection closed");
                close(client_sock);
                close(remote_sock);
                client_sock = 0;
                remote_sock = 0;
            }
        }
    }

    return 0;
}
```

The code above starts by setting up the local listener, which awaits connections from the original source we wish to proxy. Once the socket is properly set up, it's file descriptor will be stored in the **listen_sock** variable.

```c
    status = setup_local_listener(&listen_sock);
    if (status < 0)
    {
        puts("main: Failed to setup local listener.");
        return 1;
    }
```

## Tunnelling

Before we get into the technical implementation of tunneling, let's take a look at the environment we'll be moving our packets through (docker-compose).

```shell
services:
  private-web:
    build: ./private-web/
    networks:
      private:
        ipv4_address: 172.21.0.3
    ports:
      - "80"
    command: python -m http.server 80
    volumes:
      - ./private-web/contents/:/var/www/html/
  private-host:
    build: ./private-host/
    networks:
      private:
        ipv4_address: 172.21.0.2
      public:
        ipv4_address: 172.21.1.2
    command: nc -lp 31337
    volumes:
      - ./private-host/contents/:/home/user/
  public-host:
    build: ./public-host/
    networks:
      public:
        ipv4_address: 172.21.1.3
    ports:
      - "1336"
      - "1337"
    command: nc -lp 31337
    volumes:
      - ./public-host/contents/:/home/user/

networks:
  private:
    ipam:
      config:
        - subnet: 172.21.0.0/24
          gateway: 172.21.0.1
  public:
    ipam:
      config:
        - subnet: 172.21.1.0/24
          gateway: 172.21.1.1
```

![Tunnel to Private Web](/images/tunnel-to-priv-web.gif)
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

I'd also like to point out that a tunnel also usually involves encapsulating data into a pre-existing protocol (http, icmp, dns, your own custom protocol, etc.). We're not going to implement that piece here, but will likely do it in a follow on post. This post focuses on taking in a connection and forwarding it to a destination, while also bypassing potential blocks along the way.

## Proxying Summary

To build towards the concept of tunneling, we'll start by implementing a simple proxy. Proxies are fairly simple and most people are familiar with them, making them a great starting point. The proxy I'll be demonstrating in this tutorial is purposefully as simple as possible. For that reason it is not at all ready for any sort of deployment (don't use it). This also goes for the tunneling code shown later. Perhaps as we build on these techniques in future tutorials, we'll approach something remotely deployable. 

The concept of a proxy is straight forward enough. A proxy simply acts as a forwarding agent for any of your network traffic. In this case we'll be focusing on [TCP](https://www.fortinet.com/resources/cyberglossary/tcp-ip#:~:text=TCP%20stands%20for%20Transmission%20Control,data%20and%20messages%20over%20networks.) based communications, but similar methodologies would allow this to also be expanded to [UDP](https://www.techtarget.com/searchnetworking/definition/UDP-User-Datagram-Protocol#:~:text=User%20Datagram%20Protocol%20(UDP)%20is,provided%20by%20the%20receiving%20party.). In our example, we'll create a bare bones TCP traffic forwarder that will listen for connections on a specified port, and forward the received traffic to a specified destination.  

![Proxy](/images/proxy.gif)

## Proxy Main

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

    status = setup_remote_sock(&remote_sock);
    if (status != 0)
    {
        puts("main: Failed to setup remote socket.");
        return 1;
    }

    while(1){ 
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

## Proxy Listen

Let's take a look at how we're accomplishing this:

```c
/**
 * @brief Sets up the local listener socket
 * 
 * @param listen_sock pointer to socket fd to setup
 * @return int error code
 */
int setup_local_listener(int *listen_sock)
{
    int status = 0;
    struct sockaddr_in listen_addr = {0};

    listen_addr.sin_family = AF_INET;
    status = inet_pton(AF_INET, LISTEN_ADDR, &(listen_addr.sin_addr));
    if (status != 1)
    {
        perror("setup_local_listener inet_pton");
        return -1;
    }
    listen_addr.sin_port = htons(LISTEN_PORT);

    //Create listening socket to receive proxy requests
    *listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*listen_sock == -1)
    {
        perror("setup_local_listener socket");
        return status;
    }
    status = setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if (status == -1)
    {
        perror("setup_local_listener setsockopt");
        return status;
    }
    status = bind(*listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
    if (status == -1)
    {
        perror("setup_local_listener bind");
        return status;
    }
    status = listen(*listen_sock, SOMAXCONN);
    if (status == -1)
    {
        perror("setup_local_listener listen");
        return status;
    }

    return status;
}
```

It might seem like a lot, but the vast majority of this is just error checking.

The first thing we're doing to set up the local listener is filling in the **listen_addr** struct with appropriate values. 

We'll start by converting our listening address (**LISTEN_ADDR**) to a form the linux kernel expects (an integer) via the [inet_pton](https://man7.org/linux/man-pages/man3/inet_pton.3.html) syscall.

```c
inet_pton(AF_INET, LISTEN_ADDR, &(listen_addr.sin_addr));
```

The port is already an integer, but it's in little endian format, and needs to be converted to big endian. What this basically means is that the port number needs to be converted from something our local CPU understands, to a universal network standard. The [htons](https://linux.die.net/man/3/htons) system call will handle this for us.

```c
listen_addr.sin_port = htons(LISTEN_PORT);
```

Now that our **listen_addr** struct is built, we can set up the socket itself. AF_INET refers to ipv4, and SOCK_STREAM informs the kernel we'll be using TCP. As a side note, you can do some pretty neat stuff in regards to inter-process communication (IPC) using [AF_UNIX](https://man7.org/linux/man-pages/man7/unix.7.html) sockets.

```c
*listen_sock = socket(AF_INET, SOCK_STREAM, 0);
```

Next, we'll allow our socket to be re-usable. This makes it so that our operating system won't try to prevent us from listening on the port again if the process crashes. The **&(int){1}** value basically just allows us to ignore some of the output this function provides, as we don't really care.

```c
setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
```

Lastly, we'll bind our socket to the information stored in **listen_addr*, and begin listening for connections.

```c
bind(*listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
listen(*listen_sock, SOMAXCONN);
```

We're now ready to receive connections to proxy! Of course if we actually receive any connections at this point, we'll just end up dropping them.

![charlie fail](/images/charlie-brown-fail.gif)

In order to actually receive a new connection we'll need to accept it. We'll then have a new socket associated with that connection.

```c
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
    status = fcntl(client_sock, F_SETFL, fcntl(client_sock, F_GETFL, 0) | O_NONBLOCK); // Add non-blocking to existing settings
    if (status == -1)
    {
        perror("main client_sock fnctl");
        return status;
    }
}
```

You'll see we're also altering the settings associated with the socket via the [fcntl](https://man7.org/linux/man-pages/man2/fcntl.2.html) system call. Don't worry too much about how this works, just know that the **O_NONBLOCK** flag makes the socket "non-blocking". This allows the program to keep moving even when we aren't receving new data on this socket. You'll see why this matters soon enough.

## Proxy Remote Connection

Now we have our client connected, we'll want to connect them to their destination.

```c
status = setup_remote_sock(&remote_sock);
```

The process for this is very similar to how we set up the local connection, except simpler. We don't need to bind anything or listen for connections, we simply establish a connection to the configured remote address. Once again, the resulting socket will be made non-blocking.

```c
/**
 * @brief Set up the remote socket
 * 
 * @param remote_sock target socket to proxy traffic to
 * @return int error code
 */
int setup_remote_sock(int *remote_sock)
{
    int status = 0;
    struct sockaddr_in remote_addr;

    *remote_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*remote_sock == -1)
    {
        perror("setup_remote_sock: socket");
        return -1;
    }

    remote_addr.sin_family = AF_INET;
    status = inet_pton(AF_INET, REMOTE_ADDR, &(remote_addr.sin_addr));
    if (status != 1)
    {
        perror("setup_remote_sock: inet_pton");
        return -1;
    }
    remote_addr.sin_port = htons(REMOTE_PORT);

    status = connect(*remote_sock, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
    if (status == -1)
    {
        perror("setup_remote_sock: connect");
        return status;
    }
    status = fcntl(*remote_sock, F_SETFL, fcntl(*remote_sock, F_GETFL, 0) | O_NONBLOCK);
    if (status == -1)
    {
        perror("setup_local_listener fnctl");
        return status;
    }

    return status;
}
```

Great! Our connections are set up and we're ready to exchange data. To accomplish this we'll loop continually, checking for new data from either side on each loop iteration. If there's any new data, we'll forward it to the appropriate destination.

```c
while(1){ 
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
```

And here's our data checks:

```c
/**
 * @brief Checks for new data from client/server
 * 
 * @param client_sock connected client socket
 * @param remote_sock socket connection to target host
 * @return int error code
 */
int data_checks(int client_sock, int remote_sock)
{
    int status = 0;

    char data[MAX_TCP] = {0};
    status = read(client_sock, data, sizeof(data)-1);
    if (strlen(data) > 0)
    {
        write(remote_sock, data, strlen(data)+1);
        memset(data, 0, sizeof(data));
    }
    status = read(remote_sock, data, sizeof(data)-1);
    if (strlen(data) > 0)
    {
        write(client_sock, data, strlen(data)+1);
        memset(data, 0, sizeof(data));
    }

    return status;
}
```

Here's where using non-blocking sockets is important. With our current implementation, data can go back and forth from either side at any interval. If we were using traditional blocking sockets, we'd restrict our connection to requiring the opposite side to send something back before we could continue. This might work for an http connection or something similar, but would fail for something like a remote shell or chat client.

Let's see this in action...



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
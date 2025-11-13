
/*

my_socket: socket created
my_socket: sendmsg received 20 bytes
my_socket: recvmsg sending 20 bytes
my_socket: release socket

*/
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define AF_MYPROTO 31

int main()
{
    int fd = socket(AF_MYPROTO, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    char buf[] = "Hello Kernel Socket!";
    if (send(fd, buf, strlen(buf), 0) < 0) { perror("send"); }

    char rbuf[256];
    int n = recv(fd, rbuf, sizeof(rbuf), 0);
    if (n > 0) {
        rbuf[n] = 0;
        printf("recv: %s\n", rbuf);
    }

    close(fd);
    return 0;
}


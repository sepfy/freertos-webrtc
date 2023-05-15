#ifndef UDP_SOCKET_H_
#define UDP_SOCKET_H_

#include "address.h"

typedef struct UdpSocket UdpSocket;

struct UdpSocket {

  int fd;
};

int udp_socket_open(UdpSocket *udp_socket, Address *addr);

void udp_socket_close(UdpSocket *udp_socket);

int udp_socket_sendto(UdpSocket *udp_socket, Address *addr, const char *buf, int len);

int udp_socket_recvfrom(UdpSocket *udp_socket, Address *addr, char *buf, int len);

#endif // UDP_SOCKET_H_


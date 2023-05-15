#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"
#include "udp.h"


int udp_socket_open(UdpSocket *udp_socket, Address *addr) {

  udp_socket->fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (udp_socket->fd < 0) {
    LOGE("Failed to create socket");
    return -1;
  }

  struct sockaddr_in sin;
  socklen_t sin_len = sizeof(sin);
  sin.sin_family = AF_INET;
  sin.sin_port = htons(addr->port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(udp_socket->fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {

    LOGE("Failed to bind socket");
    return -1;
  }

  return 0;
}

void udp_socket_close(UdpSocket *udp_socket) {

  if (udp_socket->fd > 0)
    close(udp_socket->fd);
}

int udp_get_local_address(UdpSocket *udp_socket, Address *addr) {

  struct sockaddr_in sin;

  socklen_t len = sizeof(sin);

  if (udp_socket->fd < 0) {
    LOGE("Failed to create socket");
    return -1;
  }

  if (getsockname(udp_socket->fd, (struct sockaddr *)&sin, &len) < 0) {
    LOGE("Failed to get local address");
    return -1;
  }

  memcpy(addr->ipv4, &sin.sin_addr.s_addr, 4);

  addr->port = ntohs(sin.sin_port);

  addr->family = AF_INET;

  LOGD("local port: %d", addr->port);
  LOGD("local address: %d.%d.%d.%d", addr->ipv4[0], addr->ipv4[1], addr->ipv4[2], addr->ipv4[3]);

  return 0;
}

int udp_socket_sendto(UdpSocket *udp_socket, Address *addr, const char *buf, int len) {

  if (udp_socket->fd < 0) {

    LOGE("sendto before socket init");
    return -1;
  }

  struct sockaddr_in sin;

  sin.sin_family = AF_INET;

  memcpy(&sin.sin_addr.s_addr, addr->ipv4, 4);

  //LOGD("s_addr: %d", sin.sin_addr.s_addr);

  sin.sin_port = htons(addr->port);

  int ret = sendto(udp_socket->fd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));

  if (ret < 0) {
    LOGE("Failed to sendto");
    return -1;
  }

  return 0;
}

int udp_socket_recvfrom(UdpSocket *udp_socket, Address *addr, char *buf, int len) {

  if (udp_socket->fd < 0) {

    LOGE("recvfrom before socket init");
    return -1; 
  }


  if (udp_socket->fd < 0) {

    LOGE("socket() failed");

    return -1;
  }

  struct sockaddr_in sin;

  socklen_t sin_len = sizeof(sin);

  memset(&sin, 0, sizeof(sin));

  sin.sin_family = AF_INET;

  sin.sin_port = htons(addr->port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);

  int ret = recvfrom(udp_socket->fd, buf, len, 0, (struct sockaddr *)&sin, &sin_len);
  if (ret < 0) {

    LOGE("recvfrom() failed");
    return -1;
  }

  return ret;
  
}


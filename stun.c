#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "utils.h"
#include "stun.h"

#define MAGIC_COOKIE 0x2112A442
#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_RESPONSE 0x0101
#define STUN_BINDING_ERROR_RESPONSE 0x0111
#define STUN_BINDING_INDICATION 0x0011

#define STUN_ATTRIBUTE_MAPPED_ADDRESS 0x0001
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS 0x0020

struct StunHeader {

  uint16_t type;
  uint16_t length;
  uint32_t magic_cookie;
  uint32_t transaction_id[3];

};

struct StunAttribute {

  uint16_t type;
  uint16_t length;
  uint8_t value[0];

};

struct StunMessage {

  StunHeader header;
  StunAttribute attribute[0];

};

void stun_create_binding_request(StunMessage *msg) {

  msg->header.type = htons(STUN_BINDING_REQUEST);
  msg->header.length = htons(0);
  msg->header.magic_cookie = htonl(MAGIC_COOKIE);
  msg->header.transaction_id[0] = htonl(0x12345678);
  msg->header.transaction_id[1] = htonl(0x90abcdef);
  msg->header.transaction_id[2] = htonl(0x12345678);

}

void stun_get_mapped_address(StunAttribute *attr, uint8_t *mask, Address *addr) {

  int i;

  addr->family = attr->value[1];

  if (addr->family == 0x01) {

    addr->port = ntohs(*(uint16_t *)(attr->value + 2)) ^ *((uint16_t*)mask);

    for (i = 0; i < 4; i++) {

      addr->ipv4[i] = attr->value[i + 4] ^ mask[i];
    }

  } else {

    LOGE("Not support IPv6");
  }


  LOGD("XOR Mapped Address Family: 0x%02x", addr->family); 
  LOGD("XOR Mapped Address Port: %d", addr->port);
  LOGD("XOR Mapped Address Address: %d.%d.%d.%d", addr->ipv4[0], addr->ipv4[1], addr->ipv4[2], addr->ipv4[3]);

}

void stun_parse_binding_response(StunMessage *msg, Address *addr) {

#if 0
  printf("STUN Binding Response\n");
  printf("Type: 0x%04x\n", ntohs(msg->header.type));
  printf("Length: %d\n", ntohs(msg->header.length));
  printf("Magic Cookie: 0x%08x\n", ntohl(msg->header.magic_cookie));
  printf("Transaction ID: 0x%08x 0x%08x 0x%08x\n", ntohl(msg->header.transaction_id[0]), ntohl(msg->header.transaction_id[1]), ntohl(msg->header.transaction_id[2]));
#endif

  int i = 0;

  uint8_t mask[16];

  while (i < ntohs(msg->header.length)) {

    StunAttribute *attr = (StunAttribute *)((uint8_t *)msg->attribute + i);

    LOGD("Attribute Type: 0x%04x", ntohs(attr->type));
    LOGD("Attribute Length: %d", ntohs(attr->length));

    if (ntohs(attr->type) == STUN_ATTRIBUTE_MAPPED_ADDRESS) {

      // TODO: Parse Mapped Address
      stun_get_mapped_address(attr, mask, addr);

    } else if (ntohs(attr->type) == STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS) {

      *((uint32_t *)mask) = htonl(MAGIC_COOKIE);

      stun_get_mapped_address(attr, mask, addr);
    }

    i += ntohs(attr->length) + 4;
  }

}

int stun_get_local_address(const char *stun_server, int stun_port, Address *addr) {

  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock == -1) {
    LOGE("Failed to create socket.");
    return -1;

  }
    

  // 設定伺服器的地址及埠號
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(stun_server);
  server_addr.sin_port = htons(stun_port);

  // 建立STUN Binding Request
  StunMessage msg;

  stun_create_binding_request(&msg);

  // 發送STUN Binding Request
  LOGD("Sending STUN Binding Request.");
  int n = sendto(sock, &msg, sizeof(StunHeader), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

  if (n == -1) {
    LOGE("Failed to send STUN Binding Request.");
    return -1;
  }

  // 接收STUN Binding Response

  char buf[1024];

  StunMessage *response;// = malloc(sizeof(StunMessage));

  n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);

  if (n == -1) {
    LOGD("Failed to receive STUN Binding Response.");
    return -1;
  }

  response = (StunMessage *)buf;

  if (ntohs(response->header.type) == STUN_BINDING_RESPONSE) {

    LOGD("Received STUN Binding Response.");
    stun_parse_binding_response(response, addr);

  } else {
    
    LOGE("Received STUN Binding Error Response.");
    return -1;
  }

  return 0;
}




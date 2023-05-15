#ifndef STUN_H_
#define STUN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"

typedef struct StunHeader StunHeader;

typedef struct StunAttribute StunAttribute;

typedef struct StunMessage StunMessage;

void stun_create_binding_request(StunMessage *msg);

void stun_get_mapped_address(StunAttribute *attr, uint8_t *mask, Address *addr);

void stun_parse_binding_response(StunMessage *msg, Address *addr);

int stun_get_local_address(const char *stun_server, int stun_port, Address *addr);

#endif // STUN_H_

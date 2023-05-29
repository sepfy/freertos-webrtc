
all:
	gcc -I./mbedtls/library/ -I./mbedtls/include -I./mbedtls/tests/include -I./libsrtp/include/ -L./mbedtls/library -L./libsrtp/build/ stun.c ice.c utils.c udp.c agent.c base64.c sdp.c main.c dtls_srtp.c mbedtls/tests/src/certs.c -lpthread -lmbedx509 -lmbedtls -lmbedcrypto -lsrtp2 -lcjson -o test

clean:
	rm -rf test


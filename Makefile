
all:
	gcc -I./mbedtls/library/ -I./mbedtls/include -I./mbedtls/tests/include  -L./mbedtls/library stun.c ice.c utils.c udp.c agent.c base64.c main.c dtls_srtp.c mbedtls//tests/src/certs.c -lpthread -lmbedx509 -lmbedtls -lmbedcrypto -o test

clean:
	rm -rf test


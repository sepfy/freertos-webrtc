
all:
	gcc stun.c ice.c utils.c udp.c agent.c base64.c main.c -lpthread -o test

clean:
	rm -rf test


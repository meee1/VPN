VFLAGS = --track-origins=yes --leak-check=full --show-leak-kinds=all
CFLAGS = -std=gnu11 -g -Wall -Wextra -O2 -rdynamic 

COMMON = src/vpn_config.c lib/crypto.c
CRYPTO_FLAGS = -lm -I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl/lib -lssl -lcrypto

all: build-client

rsa: build-rsa-example

aes: build-aes-example
	
build-client: src/client.c $(COMMON)
	gcc src/client.c $(COMMON) -pthread $(CFLAGS) $(CRYPTO_FLAGS) -o client.out

build-server: src/server.c $(COMMON)
	gcc src/server.c $(COMMON) $(CFLAGS) $(CRYPTO_FLAGS) -pthread -o server.out

build-rsa-example:
	gcc lib/example/rsa.c -I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl/lib -lssl -lcrypto -o ./build/rsa_server.out
	gcc lib/example/rsa_c.c -I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl/lib -lssl -lcrypto -o ./build/rsa_client.out

build-aes-example:
	gcc lib/example/AES.c -I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl/lib -lssl -lcrypto -o ./build/aes.out

client: build-client
	sudo ./client.out 127.0.0.1

server: build-server
	sudo ./server.out

clean: server.out client.out
	rm server.out client.out 
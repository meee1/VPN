#include "../includes/server.h"

#define DEBUG 0

static pthread_t tid[2];
static struct vpn_connection* current_connection;

//static const unsigned char key[] = "01234567890123456789012345678901";
static unsigned char key[32];

/**
 * stop_client - Signal function
 * @arg: potential arguments
 *
 * Closes all fd's and frees memory.
 * 
 * returns void
 */
void stop_client()
{
	restore_gateway();
	printf("\nStopped.\n");
	close(current_connection->udp_socket);
	exit(EXIT_SUCCESS);
}

struct sockaddr_in client_addr;

/**
 * thread_socket2tun - Fowards packets from socket to tun
 * @arg: potential arguments
 *
 * Fowar	ds all packets received from udp socket to tun interface.
 * 
 * 
 * returns void
 */
void* thread_socket2tun()
{
    unsigned char buffer[2555] = {0};
    struct sockaddr_in client_addrl;
    int client_struct_length = sizeof(client_addrl);

	pid_t tid = gettid();

	printf("thread_socket2tun threadid %d\n", (int)tid);

    while(1)
    {
        int rc = recvfrom(current_connection->udp_socket, buffer, 2555, 0, (struct sockaddr*)&client_addrl,(socklen_t*) &client_struct_length);
        if(rc <= 0)
        {
        	continue;
        }

		if(DEBUG)
			printf("socket2tun: %d bytes from real ip %u:%u\n", rc, client_addrl.sin_addr, ntohs(client_addrl.sin_port));

		memcpy(&client_addr, &client_addrl, sizeof(struct sockaddr_in));

		if(rc < (16+16+1))
		{
			continue;
		}

        /* Decrypt */
        unsigned char decryptedtext[2555];
        unsigned char* tag = malloc(16);
        memcpy(tag, buffer, 16);
		unsigned char IV[16];
		memcpy(IV, buffer+16, 16);

        int decrypted_len = vpn_aes_decrypt(buffer+16+16, rc-16-16, aad, strlen(aad), tag, key, IV, decryptedtext);
        if(decrypted_len < 0)
        {
            /* Verify error */
            printf("Decrypted text failed to verify\n");
			free(tag);
            continue;
        }

        current_connection->data_sent += decrypted_len;
        rc = write(current_connection->tun_fd, decryptedtext, decrypted_len);
        free(tag);
	}
}



/**
 * thread_tun2socket - Fowards packets from tun to socket
 * @arg: potential arguments
 *
 * Fowards all packets received from tun interface to udp socket.
 * 
 * 
 * returns void
 */
void* thread_tun2socket()
{
	unsigned char buffer[2555] = {0};

	pid_t tid = gettid();

	printf("thread_tun2socket threadid %d\n", (int)tid);

	while(1)
	{
        int rc = read(current_connection->tun_fd, buffer, 2555);
        if(rc <= 0)
        {
        	continue;
        }

		struct ip_hdr* hdr = (struct ip_hdr*) buffer;

		if(DEBUG)
			printf("tun2socket: %d bytes from virtual ip %u, real ip %u:%u\n", rc, hdr->saddr, client_addr.sin_addr, client_addr.sin_port);

        /* Encrypt */
        unsigned char ciphertext[2555];
        unsigned char tag[16];
        unsigned char IV[16];
        RAND_bytes(IV, 16);
        int cipher_len = vpn_aes_encrypt(buffer, rc, aad, strlen(aad), key, IV, ciphertext, tag);

        unsigned char* encrypt_tag = malloc(cipher_len+16+16);
        memcpy(encrypt_tag, tag, 16);
        memcpy(encrypt_tag+16, IV, 16);
        memcpy(encrypt_tag+16+16, ciphertext, cipher_len);

        rc = sendto(current_connection->udp_socket, encrypt_tag, cipher_len+16+16, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
        current_connection->data_recv += cipher_len;
        free(encrypt_tag);
	}
}

/**
 * start_threads - Starts the two threads for handling data.
 * @void:
 *
 * Starts two threads, one for sending data received from tun.
 * Other one puts data into tun from socket.
 * 
 * 
 * returns void
 */
static void start_threads()
{
	/* Create thread for incomming client packets */
    int err;
    err = pthread_create(&(tid[0]), NULL, &thread_socket2tun, NULL);
    if(err != 0)
    {
		printf("[ERROR] Could not create socket2tun thread.\n");
		exit(EXIT_FAILURE);
    }

    /* Create thread for incomming tun packets */
	err = pthread_create(&(tid[1]), NULL, &thread_tun2socket, NULL);
    if(err != 0)
    {
		printf("[ERROR] Could not create tun2socket thread.\n");
		exit(EXIT_FAILURE);
    }

}

int start_vpn_client()
{
	signal(SIGINT, stop_client);

	current_connection = malloc(sizeof(struct vpn_connection));
	OpenSSL_add_all_algorithms();

	/* init Key */
	//RAND_bytes(key, sizeof key);

	for (int i = 0; i < 32; ++i)
	{
		printf("%x:", key[i]);
	}
	printf("\n");

	/* Create UDP socket. */
    current_connection->udp_socket = create_udp_socket(&(current_connection->server_addr), "0");
	if(current_connection->udp_socket <= 0)
	{
		printf("[ERROR] Could not create UDP socket.\n");
		exit(EXIT_FAILURE);
	}

	/* Create TUN interface. */
	current_connection->tun_fd = create_tun_interface("192.168.0.10/24");
	if(current_connection->tun_fd <= 0)
	{
		printf("[ERROR] Could not create TUN device.\n");
		exit(EXIT_FAILURE);
	}

	/* Configure all IP routes. */
	/*int conf = configure_route((uint8_t*) route, (uint8_t*) server_ip);
	if(conf < 0)
	{
		printf("[ERROR] Could not configure ip route.\n");
		exit(EXIT_FAILURE);
	}
*/
	printf("\n\n");
	fflush(stdout);
    printf("\rVPN Server succesfully\n");

	/* Start socket / TUN threads */
	start_threads();

    while(1)
    {
        sleep(2);
        printf("\rStats - socket2tun Sent: %f kb/s, tun2socket Recv: %f kb/s", (current_connection->data_sent/1024.0)/2, (current_connection->data_recv/1024.0)/2);
        fflush(stdout);
        current_connection->data_sent = 0;
        current_connection->data_recv = 0;
    }

	return 0;
}

int main(int argc, char const *argv[])
{
	printf("hw support? %d\n",EVP_has_aes_hardware());
	start_vpn_client();
}
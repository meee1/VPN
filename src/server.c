#include "../includes/server.h"

#define DEBUG 1

/* Threads */
pthread_t tid[2];
pthread_mutex_t lock;

struct vpn_registry* registry;
struct crypto_instance* crypto;

void stop_server()
{
    printf("\nStopped.\n");
    free_vpn_registry(registry);
    pthread_mutex_destroy(&lock);
    close(registry->udp_socket);
    exit(EXIT_SUCCESS);

}

/**
 * handle_vpn_connection - Handles a incomming VPN connection
 * @conn: current connection
 *
 * State machine handshake.
 * Negotiates secret or forwards packet.
 * 
 * returns void
 */
void handle_vpn_connection(struct vpn_connection* conn, char* buffer, int rc, struct sockaddr_in client_addr)
{
    int client_struct_length = sizeof(client_addr);
    switch(conn->state)
    {
        case CONNECTED:
            rc = sendto(registry->udp_socket, crypto->pub_key, strlen(crypto->pub_key), 0, (struct sockaddr*)conn->connection, client_struct_length);
            conn->state = REGISTERED;

            if(DEBUG)
                printf("Sent public key to new client\n");

            break;

        case REGISTERED:
            ;
            struct crypto_message* msg = vpn_rsa_decrypt(crypto, buffer, rc);
            if(msg == NULL)
            {
                printf("Client sent invalid message in REGISTERED state\n");
                break;
            }

            /* Allocate memory for key and add 0 terminator */
            conn->key = malloc(msg->size);
            memcpy(conn->key, msg->buffer, msg->size);
            conn->key_length = msg->size;

            conn->state = ALIVE;
            if(DEBUG)
                printf("Registered new key for connection\n");

            char* ok = "OK";
            rc = sendto(registry->udp_socket, ok, strlen(ok), 0, (struct sockaddr*)conn->connection, client_struct_length);

            free(msg->buffer);
            free(msg);
            break;

        case ALIVE:
            ;

            /* Decrypt */
            unsigned char decryptedtext[2555];
            unsigned char* tag = malloc(16);
            memcpy(tag, buffer, 16);
            unsigned char IV[16];
            memcpy(IV, buffer+16, 16);

            int decrypted_len = vpn_aes_decrypt(buffer+16+16, rc-16-16, aad, strlen(aad), tag, conn->key, IV, decryptedtext);
            if(decrypted_len < 0)
            {
                /* Verify error */
                printf("Decrypted text failed to verify\n");
                free(tag);
                break;
            }
            free(tag);

            struct ip_hdr* hdr = (struct ip_hdr*) decryptedtext;
            //hdr->saddr = ntohl(hdr->saddr);

            if(DEBUG)
                printf("recv: %d bytes from virtual ip %d, real ip %d, subnet ip: %d\n", decrypted_len, hdr->saddr, client_addr.sin_addr.s_addr, conn->vip_out);

            /* Replace source with given out ip address  */
            //conn->vip_in = hdr->saddr;
            //hdr->saddr = conn->vip_out;
            //hdr->saddr = htonl(hdr->saddr);

            conn->data_sent += decrypted_len;
            registry->data_out += decrypted_len;
            rc = write(registry->tun_fd, decryptedtext, decrypted_len);
            break;
    }
}


/**
 * thread_socket2tun - Fowards packets from socket to tun
 * @arg: potential arguments
 *
 * Fowards all packets received from udp socket to tun interface.
 * 
 * 
 * returns void
 */
void* thread_socket2tun()
{
    char* buffer[2555] = {0};
    struct sockaddr_in client_addr;
    int client_struct_length = sizeof(client_addr);

    while(1)
    {
        int rc = recvfrom(registry->udp_socket, buffer, 2555, 0, (struct sockaddr*)&client_addr,(socklen_t*) &client_struct_length);
        if(rc <= 0)
        {
            continue;
        }

        /* look for connection in registry. */
        pthread_mutex_lock(&lock);
        struct vpn_connection* conn = get_vpn_connection_addr(registry, client_addr.sin_addr.s_addr);
        if(conn == NULL)
        {
            struct ip_hdr* hdr = (struct ip_hdr*) buffer;
            hdr->saddr = ntohl(hdr->saddr);

            conn = register_connection(registry, hdr->saddr, client_addr);
            if(conn == NULL)
            {
                printf("[warning] Cannot accept more connections!\n");
                pthread_mutex_unlock(&lock);
                continue;
            }
        }
        pthread_mutex_unlock(&lock);

        handle_vpn_connection(conn, buffer, rc, client_addr);
        
    }
}

/**
 * thread_tun2socket - Fowards packets from tun to socket
 * @arg: potential arguments
 *
 * Fowards all packets received from tun interface to udp socket.
 * 
 * returns void
 */
void* thread_tun2socket()
{
    char* buffer[2555] = {0};
    struct sockaddr_in client_addr;
    int client_struct_length = sizeof(client_addr);

    while(1)
    {
        int rc = read(registry->tun_fd, buffer, 2555);
        if(rc <= 0)
        {
            continue;
        }

        struct ip_hdr* hdr = (struct ip_hdr*) buffer;
        hdr->daddr = ntohl(hdr->daddr);

        /* Look for connection based on virtual ip inn */
        pthread_mutex_lock(&lock);
        struct vpn_connection* conn = get_vpn_connection_ip(registry, hdr->daddr);
        pthread_mutex_unlock(&lock);
        if(conn == NULL)
        {
            continue;
        }

        /* Replace destination with user chosen ip */
        hdr->daddr = conn->vip_in;
        hdr->daddr = htonl(hdr->daddr);
        
        if(DEBUG)
            printf("sending %d bytes to client real ip %d with virtual ip %d\n", rc, conn->connection->sin_addr.s_addr, hdr->daddr);

        /* Encrypt */
        unsigned char ciphertext[2555];
        unsigned char tag[16];
        unsigned char IV[16];
        RAND_bytes(IV, 16);
        int cipher_len = vpn_aes_encrypt(buffer, rc, aad, strlen(aad), conn->key, IV, ciphertext, tag);

        unsigned char* encrypt_tag = malloc(cipher_len+16+16);
        memcpy(encrypt_tag, tag, 16);
        memcpy(encrypt_tag+16, IV, 16);
        memcpy(encrypt_tag+16+16, ciphertext, cipher_len);

        rc = sendto(registry->udp_socket, encrypt_tag, cipher_len+16+16, 0, (struct sockaddr*)conn->connection, client_struct_length);
        conn->data_recv += rc;
        registry->data_in += rc;
        free(encrypt_tag);
    }
}

/**
 * start_server - Main event loop for server
 * @network: nework ip with cidr
 *
 * Creates and configures everything for VPN
 * Creates threads and handles main loop
 * 
 * returns void
 */
void start_server(const char* network)
{
    signal(SIGINT, stop_server);
    OpenSSL_add_all_algorithms();

    /* Create a new VPN registry */
    registry = create_registry((uint8_t*) network);

    /* Create Crypto instance */
    crypto = crypto_init();

    struct sockaddr_in server;
    registry->udp_socket = create_udp_socket(&server, "0");
    registry->tun_fd = create_tun_interface(network);

    /*
    int conf = configure_ip_forwarding(network);
    if(conf < 0)
    {
        printf("[ERROR] Could not configure iptables!\n");
        exit(EXIT_FAILURE);
    }
    */
    /* init lock for threads */
    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        exit(EXIT_FAILURE);
    }

    /* Create thread for incomming client packets */
    int err;
    err = pthread_create(&(tid[0]), NULL, &thread_socket2tun, NULL);
    if(err != 0){
        printf("\ncan't create thread :[%s]", strerror(err));
    }


    /* Create thread for incomming tun packets */
    err = pthread_create(&(tid[1]), NULL, &thread_tun2socket, NULL);
    if(err != 0){
        printf("\ncan't create thread :[%s]", strerror(err));
    }

    while(1)
    {
        sleep(3);

        printf("\rConnected Users: %d, Sending: %d kb/s, Receving: %d kb/s", registry->size, (registry->data_in/1024)/3, (registry->data_out/1024)/3);
        fflush(stdout);

        //pthread_mutex_lock(&lock);
        //registry_check_timeout(registry);
        //pthread_mutex_unlock(&lock);

        registry->data_in = 0;
        registry->data_out = 0;
    }
}

int main()
{
    start_server("192.168.88.0/31");
    /* code */
    return 0;
}

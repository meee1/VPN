#include "../includes/vpn_config.h"

static char* gateway;
/**
 * restore_gateway - Restores saved gateway
 * @void:
 *
 * Restores the last saved gateway when program exits.
 * 
 * returns 1.
 */
int restore_gateway()
{
	char cmd [1000] = {0x0};
    #ifdef __APPLE__
    sprintf(cmd,"route add default %s", gateway);
    #endif

    #ifdef __linux__
    sprintf(cmd,"ip route add default via %s", gateway);
    #endif

    int sys = system("route delete default");
    sys = system(cmd);

    return sys;
}

/**
 * save_current_gateway - Saves the current gateway.
 * @void:
 *
 * Saves the current gateway address to be able
 * to restore it when program exists.
 * 
 * returns 1.
 */
static int save_current_gateway()
{
	char cmd [1000] = {0x0};

    #ifdef __APPLE__
    sprintf(cmd,"route -n get default | grep gateway | cut -d ':' -f 2 | awk '{$1=$1};1'");
    #endif
    #ifdef __linux__
    sprintf(cmd,"/sbin/ip route | awk '/default/ { print $3 }'");
    #endif

    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL){
        gateway = malloc(strlen(line)+1);
        strcpy(gateway, line);
    }
    pclose(fp);

    return 1;
}

/**
 * configure_route - configures IP route.
 * @route: route to add
 * @server_ip: ip of vpn server.
 *
 * Configures IP routes to forward traffic
 * to tun device, but allow traffic out to 
 * vpn server.
 * 
 * returns 1
 */
int configure_route(uint8_t* route, uint8_t* server_ip)
{
	int save = save_current_gateway();
	if(save <= 0)
	{
		printf("[ERROR] Could not save current gateway!\n");
		exit(EXIT_FAILURE);
	}

    /* Delete route and add new. */
    char cmd [1000] = {0x0};
    sprintf(cmd,"route delete %s", route);
	int sys = system(cmd);

    #ifdef __APPLE__
    sprintf(cmd,"route add %s 10.0.0.255", route);
    #endif

    #ifdef __linux__
    sprintf(cmd,"ip route add %s via 10.0.0.1", route);
    #endif

    sys = system(cmd);

	/* Add rule to allow traffic to vpn server */
    #ifdef __APPLE__
    sprintf(cmd,"route add %s %s", server_ip, gateway);
    #endif

    #ifdef __linux__
    sprintf(cmd,"ip route add %s via %s", server_ip, gateway);
    #endif

    sys = system(cmd);

    return sys;
}

 static inline in_addr_t *as_in_addr(struct sockaddr *sa) {
     return &((struct sockaddr_in *)sa)->sin_addr.s_addr;
 }

/**
 * create_tun_interface - Opens a tun device.
 * @virtual_subnet: subet for ifconfig (needed for linux.)
 *
 * Creates and opens tun0 interface device.
 * Also configurates the tun0 device to point
 * to correct virtual subnet.
 * 
 * returns fd of device or -1 on error.
 */
int create_tun_interface(char* virtual_subnet)
{
    int fd = -1;

    int mtu = 0;
    struct ifreq ifr;
    int err;

    if( (fd = open("/dev/tun", O_RDWR | O_NONBLOCK)) == -1 ) {
        if( (fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) == -1 ) {
           printf("open /dev/net/tun");           
           exit(1);
        }
    }

    //char* devname = "tun0";
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    //strncpy(ifr.ifr_name, devname, IFNAMSIZ); // devname = "tun0" or "tun1", etc

    /* ioctl will use ifr.if_name as the name of TUN
         * interface to open: "tun0", etc. */
    if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) == -1 ) {
        printf("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

/*
    // Activate interface.
    ifr.ifr_flags = IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
        printf("Cannot activate %s: %s", ifr.ifr_name, strerror(errno));
        goto error;
    }
*/

    char cmd [1000] = {0x0};

    char* currentip;
    FILE* fp = popen("getprop sys.device.ip.address", "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL){
        currentip = malloc(strlen(line)+1);
        strcpy(currentip, line);
    }
    pclose(fp);

    int pos = strlen(currentip)-1-2;
    int partip = atoi(currentip+pos);

    printf("Current IP: %s %u\n", currentip, partip);

    free(currentip);

    // change existing interface
    sprintf(cmd,"ifconfig lmi40 192.168.64.%d/24",partip);
    //printf("%s\n",cmd);
    int sys = system(cmd);

    // add new route
    sprintf(cmd,"ip route add table local_network 192.168.64.0/24 dev lmi40");
    sys = system(cmd);
    if(sys < 0)
    {
        sprintf(cmd,"ip route add 192.168.64.0/24 dev lmi40");
        sys = system(cmd);
    }

    // bring up the interface and set mtu
    sprintf(cmd,"ifconfig %s %s up mtu 1440", ifr.ifr_name, virtual_subnet);
    sys = system(cmd);
    if(sys < 0)
    {
        printf("Could not activate tun device!\n");
        exit(EXIT_FAILURE);
    }

    sprintf(cmd,"ip route add table local_network 192.168.0.0/24 dev %s",ifr.ifr_name);
    sys = system(cmd);
/*
    // Set MTU if it is specified.
    ifr.ifr_mtu = mtu;
    if (mtu > 0 && ioctl(fd, SIOCSIFMTU, &ifr)) {
        printf("Cannot set MTU on %s: %s", ifr.ifr_name, strerror(errno));
        goto error;
    }
*/
    char address[65];
    int prefix;
    int chars;
    int count = 0;

    while (sscanf(virtual_subnet, " %64[^/]/%d %n", address, &prefix, &chars) == 2) {
        virtual_subnet += chars;

        if (inet_pton(AF_INET, virtual_subnet, as_in_addr(&ifr.ifr_addr)) != 1 ||
                prefix < 0 || prefix > 32) {
            count = -2;
            break;
        }

        if (ioctl(fd, SIOCSIFADDR, &ifr)) {
            count = (errno == EINVAL) ? -2 : -1;
            break;
        }

        in_addr_t mask = prefix ? (~0 << (32 - prefix)) : 0;
        *as_in_addr(&ifr.ifr_netmask) = htonl(mask);
        if (ioctl(fd, SIOCSIFNETMASK, &ifr)) {
            count = (errno == EINVAL) ? -2 : -1;
            break;
        }
    }

    return fd; 

error:
    close(fd);
    return -1;
}

/**
 * create_udp_socket - Opens a tun device.
 * @server_addr: sockaddr_in to configure
 * @server_ip: IP that socket should connect too.
 *
 * Creates UDP socket and configures sockaddr_in
 * to point to correct server ip and sin_family.
 * 
 * returns fd of device or -1 on error.
 */
int create_udp_socket(struct sockaddr_in* server_addr, uint8_t* server_ip)
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0){
          perror("sock:");
          exit(1);
    }

    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(VPN_PORT);

    /* If server_ip is NOT INADDR_ANY then assign and return.    */
    if(strcmp((char*)server_ip, "0") != 0){
        server_addr->sin_addr.s_addr = inet_addr((char*) server_ip);
        return sockfd;
    }
    server_addr->sin_addr.s_addr = INADDR_ANY;

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0){
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if(bind(sockfd, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0){
        printf("Couldn't bind to the port\n");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

/**
 * configure_ip_forwarding - Configures IP
 * @virtual_subnet: ip of the virtual subnut
 *
 * Uses ifconfig to assign IP to tun device.
 * Uses iptables to enable ip forwarding
 * and creates MASQUERADE for outgoing traffic.
 * 
 * returns value of system command.
 */
int configure_ip_forwarding(char* virtual_subnet)
{
    char cmd [1000] = {0x0};
    int sys = system("sysctl -w net.ipv4.ip_forward=1");

    sprintf(cmd,"iptables -t nat -A POSTROUTING -s %s ! -d %s -m comment --comment 'vpn' -j MASQUERADE", virtual_subnet, virtual_subnet);
    sys = system(cmd);

    sprintf(cmd,"iptables -A FORWARD -s %s -m state --state RELATED,ESTABLISHED -j ACCEPT", virtual_subnet);
    sys = system(cmd);

    sprintf(cmd,"iptables -A FORWARD -d %s -j ACCEPT", virtual_subnet);
    sys = system(cmd);

    return sys;
}

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

extern unsigned char key[32];

unsigned char* hexstr_to_char(const char* hexstr)
{
    size_t len = strlen(hexstr);
    size_t final_len = len / 2;
    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}

void getKey()
{
    FILE* fp = popen("getprop persist.sys.d2d.calibrated", "r");
    char line1[256]={0x0};

    if(fgets(line1, sizeof(line1), fp) != NULL)
    {
    }
    pclose(fp);

    fp = popen("getprop persist.sys.d2d.dl.frequency", "r");
    char line2[256]={0x0};

    if(fgets(line2, sizeof(line2), fp) != NULL)
    {
    }
    pclose(fp);
    
    memcpy(key, line1, strlen(line1));
    memcpy(key+8, line2, strlen(line2));
    memcpy(key+16, line2, strlen(line2));

    for (int i = 0; i < 32; ++i)
	{
		//printf("%x:", key[i]);
	}
	//printf("\n");

    fp = popen("getprop persist.key", "r");
    char line3[256]={0x0};

    if(fgets(line3, sizeof(line3), fp) != NULL)
    {
    }
    pclose(fp);
    
    int length = strlen(line3);
    if(length >= 64) {
        unsigned char * hex = hexstr_to_char(line3);

        memcpy(key, hex, 32);

        free(hex);

        for (int i = 0; i < 32; ++i)
        {
            //printf("%x:", key[i]);
        }
        //printf("\n");
    }
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

    if( (fd = open("/dev/tun", O_RDWR)) == -1 ) {
        if( (fd = open("/dev/net/tun", O_RDWR)) == -1 ) {
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

    if(strlen(line) > 0)
    {
        int pos = strlen(currentip)-1-2;
        int partip = atoi(currentip+pos);

        printf("Current IP: %s %u\n", currentip, partip);

        free(currentip);

        // change existing interface
        sprintf(cmd,"ifconfig lmi40 192.168.64.%d/24",partip);
        int sys = system(cmd);

        // add new route
        sprintf(cmd,"ip route add table local_network 192.168.64.0/24 dev lmi40");
        sys = system(cmd);
        if(sys < 0)
        {
            sprintf(cmd,"ip route add 192.168.64.0/24 dev lmi40");
            sys = system(cmd);
        }



        // remove old vxlan
        system("ip link delete vxlan1");
        // create new vxlan
        sprintf(cmd,"ip link add vxlan1 type vxlan id 1 remote 192.168.0.%d dstport 4789",partip);
        sys = system(cmd);
        // set vxlan mtu
        system("ifconfig vxlan1 up mtu 1420");
        // add vxlan to bridge
        system("/bin/busybox brctl addif br-vxlan vxlan1");
        // add fdb entry
        sprintf(cmd,"bridge fdb append to 00:00:00:00:00:00 dev vxlan1 dst 192.168.0.%d",partip);
        sys = system(cmd);


        //ip -d link show vxlan1

    }

    // bring up the interface and set mtu
    sprintf(cmd,"ifconfig %s %s up mtu 1480", ifr.ifr_name, virtual_subnet);
    int sys = system(cmd);
    if(sys < 0)
    {
        printf("Could not activate tun device!\n");
        exit(EXIT_FAILURE);
    }

    sprintf(cmd,"ip route add table local_network 192.168.0.0/24 dev %s",ifr.ifr_name);
    sys = system(cmd);

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

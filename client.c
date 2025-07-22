#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>


#define SERVER_PORT "14444"
#define BUFFER_SIZE 65536
#define INTERVAL 2
#define DURATION 30

/*  stdio.h, stdlib.h, string.h, unistd.h: C standard I/O and memory functions.      
    sys/types.h, sys/socket.h, netinet/in.h, arpa/inet.h: For sockets and networking.
    netdb.h: For getaddrinfo() and related DNS utilities.
    errno.h: To handle and print system call errors.*/


void *get_in_addr(struct sockaddr *sa) { //helper function when getaddrinfo() gives us an address structure
    //extract the ipv4 address (sin_addr) from a generic struct sockaddr pointer.
    return &(((struct sockaddr_in*)sa)->sin_addr);
}

/*
struct sockaddr {
    unsigned short sa_family;   // Address family (AF_INET for IPv4)
    char sa_data[14];           // Protocol-specific address data
};

struct sockaddr_in {
    short int          sin_family;  // AF_INET
    unsigned short int sin_port;    // Port number (network byte order)
    struct in_addr     sin_addr;    // IP address
    char               sin_zero[8]; // Padding (unused)
sockaddr_in
    we can cast between the two in system calls:
    connect(sockfd, (struct sockaddr *)&their_addr, sizeof their_addr);

};
*/

int main(int argc, char *argv[]) {
    int sockfd; //the fd of the connected tcp socket
    struct addrinfo hints, *servinfo, *p; 
    // *servinfo-> pointer to linked list of address results from getaddrinfo
    // *p -> iterator for the linked list to try each address, might be more than 1 address for the server
    int rv; // stores the return of getaddrinfo
    char s[INET_ADDRSTRLEN];  // To hold the printable IP

    if (argc != 2) {
        fprintf(stderr, "usage: %s <server-ip-address>\n", argv[0]);
        exit(1);
    }

    // hints -> specifies what type of address we want in getaddrinfo
    memset(&hints, 0, sizeof hints); // set every byte of the structure to 0, initializes the structure clean
    hints.ai_family = AF_INET;        // asks for IPv4 only for this server 
    hints.ai_socktype = SOCK_STREAM;  // TCP

    printf("Calling getaddrinfo() for host: %s, port: %s\n", argv[1], SERVER_PORT);

    //int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
    if ((rv = getaddrinfo(argv[1], "14444", &hints, &servinfo)) != 0) {
        fprintf(stdout, "[ERROR] getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    printf("Starting connection attempt...\n");
    for (p = servinfo; p != NULL; p = p->ai_next) {
        //servinfo is the head of the linked list returned by getaddrinfo
        printf("Trying socket creation...\n");

    // p -> ai.addr is a pointer to struct sockaddr, specifies address type (from getaddrinfo)
    // p -> ai.socktype is the type of socket (tcp/udp), SOCK_STREAM for tcp
    // p -> ai.protocol is the type of protocol to use, 0 is the default protocol for the given family and socktype
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
        perror("client: socket");
        continue;
    }
    printf("Socket created, trying connect...\n");


    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(sockfd);
        perror("client: connect");
        continue;
    }
    printf("Connect succeeded.\n");


    break; // success
}

    if (p == NULL) {
            fprintf(stderr, "client: failed to connect\n");
            return 2;
        }

     // Convert the binary IP to a string to print the confirmation msg
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    printf("Connecting to %s\n", s);

    freeaddrinfo(servinfo); // free the memory allocated from the linked list *servinfo of type struct addrinfo

    ////// Sending data /////

    char buffer[BUFFER_SIZE]; // We create the buffer
    memset(buffer, 'A', sizeof(buffer));  // Fill buffer with dummy data to send, the character 'A'

    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);  // Capture start time

    long total_bytes_sent = 0;
    long interval_bytes_sent = 0;

    int duration_seconds = DURATION;
    int interval_seconds = INTERVAL;

    double next_print_time = interval_seconds;

    while (1) {

    // Check current time
    gettimeofday(&current_time, NULL);
    double elapsed = (current_time.tv_sec - start_time.tv_sec) +
                     (current_time.tv_usec - start_time.tv_usec) / 1e6;

    // Print throughput every INTERVAL (2) seconds, catch up and print missed intervals if RSSI is bad
    while (elapsed >= next_print_time) {
        double mbps = (interval_bytes_sent * 8.0) / 1e6 / interval_seconds;
        printf("[%.0fs] : %.2f Mbps\n", next_print_time, mbps);
        next_print_time += interval_seconds;
        interval_bytes_sent = 0;
    }

    // Exit after DURATION (30) seconds
    if (elapsed >= duration_seconds) {
        break;
    }

        // Send the buffer
    ssize_t bytes_sent = send(sockfd, buffer, BUFFER_SIZE, 0);
    if (bytes_sent < 0) {
        perror("client: send");
        break;
    }

    total_bytes_sent += bytes_sent;
    interval_bytes_sent += bytes_sent;
}

    // After the loop, printing final stats
    double total_mbps = (total_bytes_sent * 8.0) / 1e6 / duration_seconds;
    printf("Total throughput: %.2f Mbps\n", total_mbps);

    close(sockfd);

    return 0;
}
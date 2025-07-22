#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 14444
#define TCP_BACKLOG 1
#define BUFSIZE 65536
#define INTERVAL 2
#define DURATION 30


int server_setup (){
    int sockfd;
    struct sockaddr_in address;

    //create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { // 0 -> ( find the proper protocol )
        perror("socket");
        exit(1);
    }

    //reuse
    int yes=1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    address.sin_family = AF_INET; //IPv4
    address.sin_port = htons(PORT); //define port, htons make it in big endian
    address.sin_addr.s_addr = INADDR_ANY; //accept multiple interfaces
    memset(&(address.sin_zero), '\0', 8); //padding with zero


    // map server in ip + port
    if (bind(sockfd, (struct sockaddr *)&address, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    }

    // ready to receive
    if (listen(sockfd, TCP_BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    return sockfd;

}


double get_real_time() {
    /* function to get time with accurancy*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

void handle_client(int client_sock) {

    char buffer[BUFSIZE];
    ssize_t bytes_received;
    long long total_bytes = 0;
    long long interval_bytes = 0;

    double start_time = get_real_time();
    double next_interval = start_time + INTERVAL;
    double end_time = start_time + DURATION;

    printf("Speed test started for this client...\n");

    while (1) {
        bytes_received = recv(client_sock, buffer, BUFSIZE, 0);
        if (bytes_received <= 0) {
            break;
        }

        total_bytes += bytes_received;
        interval_bytes += bytes_received;

        double now = get_real_time();

        //auto itan if(now >= next_interval)
        while (now >= next_interval) {
            double throughput = (interval_bytes * 8.0) / (INTERVAL * 1e6); //  Mbps
            printf("[%.1f sec] Throughput: %.2f Mbps\n", next_interval - start_time, throughput);
            //to panw prin itan printf("[%.1f sec] Throughput: %.2f Mbps\n", now - start_time, throughput);
            // to ekana next_interval - start_time gia na kanei swsta log ton xrono kai na mh
            // stamataei na tupwnei ton xrono otan exoume delay, opote de to allazoume
            interval_bytes = 0;
            next_interval += INTERVAL;
        }

        if (now >= end_time) {
            break;
        }
    }

    double avg_throughput = (total_bytes * 8.0) / (DURATION * 1e6);
    printf("Total throughput over %.0f sec: %.2f Mbps\n\n", (double)DURATION, avg_throughput);
}


int main(int argc, char *argv[]) {

    int server_sock = server_setup();

    while (1) {
        printf("Waiting for a client to connect...\n");

        struct sockaddr_in client_addr;
        socklen_t addr_size = sizeof(client_addr);

        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_size);
        if (client_sock == -1) {
            perror("accept");
            continue;
        }

        printf("Client connected from %s\n", inet_ntoa(client_addr.sin_addr));

        handle_client(client_sock);

        close(client_sock);
        printf("Client disconnected.\n\n");
    }

    close(server_sock);
    return 0;
}
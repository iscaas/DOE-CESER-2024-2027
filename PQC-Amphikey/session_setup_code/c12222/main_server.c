/**
 * main_server.c
 *
 * This program acts as a persistent C12.22 UDP server. It listens for incoming
 * C12.22 request packets on a specified port, processes them using the
 * existing ANSI C12.22 library functions, and sends the appropriate
 * response back to the client.
 *
 * How to Compile:
 * Place this file in the same 'src' directory as the other C12.22 source files.
 * Compile using the following command:
 * gcc -o c1222_server main_server.c ansi_c1222.c ansi_c1218.c ansi_tblmgr.c aes.c eax.c crc.c -lm
 *
 * How to Run:
 * ./c1222_server
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>     // For uint8_t and other fixed-width types
#include <sys/socket.h> // For socket programming functions and types
#include <arpa/inet.h>  // For inet_ntop and other network functions
#include <netinet/in.h> // For sockaddr_in structure

// Include the necessary headers from the C12.22 project
#include "ansi_c1222.h"
#include "ansi_c1218.h"

#define SERVER_PORT 1153
#define BUFFER_SIZE 1024

// A wrapper function to process an incoming C12.22 packet and generate a response.
// This encapsulates the logic from the original TestC1222SingleFrame function.
// It returns the length of the generated response packet.
int process_c1222_request(uint8_t* request_data, int request_len, uint8_t* response_data) {
    uint8_t *pUserPsemData = NULL;
    int response_len = 0;

    // Initialize the C12.22 library for a new transaction
    InitC1222AcseInfo();

    // Parse the incoming ACSE PDU
    ParseC1222AcsePdu(request_data);

    // If user information was found, parse the inner EPSEM frame
    if (g_user_info.nSize != 0) {
        pUserPsemData = ParseC1222EpsemFrame(g_user_info.pData);

        // Check if a response is required based on the EPSEM control byte
        if (g_ansiC1222Status.ctrlByte.bits.RESPONSE_CONTROL == E_EPSEM_ALWAYS_RESP) {
            // Build the full C12.22 response packet
            stEpsemPayload epsemPayload;
            stEpsemFrame   epsemFrame;

            // 1. Build the EPSEM payload (the actual data/response)
            memset(&epsemPayload, 0x00, sizeof(epsemPayload));
            BuildC1222EpsemPayload(pUserPsemData, &epsemPayload);

            // 2. Wrap the payload in an EPSEM frame
            memset(&epsemFrame, 0x00, sizeof(epsemFrame));
            epsemFrame.pEpsemPayload = &epsemPayload; // Point to the payload
            BuildC1222EpsemFrame(&epsemPayload, &epsemFrame);

            // 3. Wrap the EPSEM frame in the final ACSE PDU and get its length
            response_len = BuildC1222AcsePdu(&epsemFrame, response_data);

        } else {
            printf("Request received, but no response is required.\n");
            response_len = 0;
        }
    } else {
        printf("Could not parse user info from the request.\n");
        response_len = 0;
    }

    return response_len;
}


int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    uint8_t received_data[BUFFER_SIZE];
    uint8_t response_data[BUFFER_SIZE];

    // 1. Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    // 2. Configure server address and bind socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on any of the VM's IP addresses
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("C12.22 Server listening on UDP port %d...\n", SERVER_PORT);

    // 3. Main server loop
    while (1) {
        client_len = sizeof(client_addr);

        // Wait for and receive a request from a client (e.g., the Raspberry Pi)
        int len = recvfrom(sockfd, received_data, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        
        if (len > 0) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("\nReceived %d bytes from client %s\n", len, client_ip);

            // 4. Process the received C12.22 data and generate a response
            int response_len = process_c1222_request(received_data, len, response_data);

            // 5. Send the response back to the client if one was generated
            if (response_len > 0) {
                sendto(sockfd, response_data, response_len, 0, (const struct sockaddr *)&client_addr, client_len);
                printf("Sent %d byte response back to %s\n", response_len, client_ip);
            }
        }
    }

    close(sockfd);
    return 0;
}


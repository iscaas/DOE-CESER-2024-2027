/*
 * =====================================================================================
 *
 * Filename:  main.c (Server Version)
 *
 * Description:  A persistent C12.22 TCP server that listens for client connections.
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ansi_c1222.h" // Project's C12.22 functions

#define PORT 1153       // The standard C12.22 port
#define BUFFER_SIZE 1024

// Forward declaration for the function that handles the C12.22 logic
void process_c1222_request(uint8_t* request_data, int request_len, uint8_t* response_data, int* response_len);
void print_hex_server(const char* title, const unsigned char* data, int len);

/**
 * @brief Handles an incoming client connection.
 *
 * This function reads a request from a client, processes it using the C12.22
 * library functions, and sends the generated response back.
 *
 * @param client_socket The socket descriptor for the connected client.
 */
void handle_connection(int client_socket) {
    uint8_t request_buffer[BUFFER_SIZE] = {0};
    uint8_t response_buffer[BUFFER_SIZE] = {0};
    int response_len = 0;

    // Read the incoming request from the client
    int bytes_read = read(client_socket, request_buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        print_hex_server("Received Request", request_buffer, bytes_read);

        // Process the request and generate a response
        process_c1222_request(request_buffer, bytes_read, response_buffer, &response_len);

        if (response_len > 0) {
            print_hex_server("Sending Response", response_buffer, response_len);
            // Send the response back to the client
            write(client_socket, response_buffer, response_len);
        } else {
            printf("No response generated.\n");
        }
    } else if (bytes_read == 0) {
        printf("Client disconnected.\n");
    } else {
        perror("Read error");
    }

    // Close the connection with this client
    close(client_socket);
    printf("Connection closed.\n\n");
}


int main(int argc, char const* argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    printf("--- C12.22 Server Starting ---\n");

    // 1. Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // 2. Set socket options to allow reusing the address and port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all available network interfaces
    address.sin_port = htons(PORT);

    // 3. Bind the socket to the network address and port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // 4. Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n\n", PORT);

    // 5. Enter the main server loop to accept connections
    while (1) {
        printf("Waiting for a new connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue; // Continue to the next iteration to wait for another connection
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Connection accepted from %s:%d\n", client_ip, ntohs(address.sin_port));

        // Handle the connection in a separate function
        handle_connection(new_socket);
    }

    return 0;
}


/**
 * @brief Wrapper for the existing C12.22 processing logic.
 *
 * This function takes a raw request, calls the project's parsing and response
 * building functions, and returns the generated response.
 *
 * @param request_data Raw bytes of the C12.22 request.
 * @param request_len Length of the request data.
 * @param response_data Buffer to store the generated response.
 * @param response_len Pointer to store the length of the response.
 */
void process_c1222_request(uint8_t* request_data, int request_len, uint8_t* response_data, int* response_len) {
    uint8 *pUserPsemData = NULL;

    // Use the existing global variables from ansi_c1222.c
    extern stTestData g_output_data;
    extern stAnsiC1222Status g_ansiC1222Status;
    extern stElement g_user_info;

    // Initialize the C12.22 state machine
    InitC1222AcseInfo();

    // Parse the full ACSE PDU
    ParseC1222AcsePdu(request_data);

    if (g_user_info.nSize > 0) {
        // Parse the EPSEM frame to get to the service request
        pUserPsemData = ParseC1222EpsemFrame(g_user_info.pData);

        // Check if a response is required
        if (g_ansiC1222Status.ctrlByte.bits.RESPONSE_CONTROL == E_EPSEM_ALWAYS_RESP) {
            // Build the full response PDU
            // The result is stored in the global g_output_data
            BuildC1222Resp(pUserPsemData, g_output_data.pData);

            // The total length of the response is in the second byte of the PDU
            *response_len = g_output_data.pData[1] + 2;
            memcpy(response_data, g_output_data.pData, *response_len);
        } else {
            *response_len = 0;
        }
    }
}

/**
 * @brief Prints a byte buffer in a formatted hexadecimal view for the server.
 */
void print_hex_server(const char* title, const unsigned char* data, int len) {
    printf("%s (%d bytes):\n", title, len);
    for (int i = 0; i < len; ++i) {
        printf("0x%02X ", data[i]);
        if ((i + 1) % 10 == 0 && i < len -1) {
            printf("\n");
        }
    }
    printf("\n----------------------------------------\n");
}


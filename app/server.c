#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
  uint16_t id;
  uint8_t flags[2];
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} dns_header_t;

typedef struct {
  size_t len;
  char content[];
} label_t;

typedef struct {
  uint16_t type;
  uint16_t class;
  size_t name_len;
  label_t *name[];
} dns_query_t;

// temporary before creating a header encoder
#define QR_MASK                                                                \
  (1 << 7); // 100000000, only QR is set to 1 and everything else is set to 0

void parse_query(dns_query_t *query, char buf[]);

int main() {
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int udpSocket, client_addr_len;
  struct sockaddr_in clientAddress;

  udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udpSocket == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting REUSE_PORT
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEPORT failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(2053),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(udpSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  int bytesRead;
  char buffer[512];
  socklen_t clientAddrLen = sizeof(clientAddress);

  uint16_t id = 1234;

  while (1) {
    // Receive data
    bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&clientAddress, &clientAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data");
      break;
    }

    buffer[bytesRead] = '\0';
    printf("Received %d bytes: %s\n", bytesRead, buffer);

    dns_header_t response = {0};
    response.id = htons(1234);
    response.flags[0] |= QR_MASK;

    dns_query_t *query = malloc(sizeof(dns_query_t));
    parse_query(query, buffer);

    // Send response
    if (sendto(udpSocket, &response, sizeof(response), 0,
               (struct sockaddr *)&clientAddress,
               sizeof(clientAddress)) == -1) {
      perror("Failed to send response");
    }
  }

  close(udpSocket);

  return 0;
}

void parse_query(dns_query_t *query, char buf[]) {
  size_t offset = 12; // skip the header

  query->class = 1;
  query->type = 1;

  while (buf[offset] != '\0') {
    printf("buf: %c", buf[offset]);
    size_t label_len = buf[offset];
    label_t *label = malloc(sizeof(label_t) + label_len + 1);
    label->len = label_len;
    for (int i = 0; i <= label_len; i++) {
      label->content[i] = buf[offset + i + 1];
    }
    label->content[label_len] = '\0';
    label_t *new_name = realloc(query->name, sizeof(label_t) * (query->name_len + 1) + label->len);
    if (new_name == NULL) {
      perror("realloc failed");
      free(label);
      exit(1);
    }
    dns_query_t *new_query = realloc(query, sizeof(dns_query_t) + sizeof(label_t) * (query->name_len + 1) + label->len);
    if (new_query == NULL) {
      perror("realloc failed");
      free(label);
      exit(1);
    }
    query = new_query;

    memcpy(&query->name[query->name_len], label, sizeof(label_t) + label_len + 1);
    query->name_len++;
    offset += label_len + 1;
  }
}

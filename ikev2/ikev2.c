/*
 */
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include "../common/parser.h"
#include "../common/log.h"

FILE *fp;
FILE *fikev2Stats;

void ikev2Display (void *buf, int bytes, jsonData_t* jsonData) {
    int i;
    struct iphdr *ip = buf;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN);
    i = inet_ntoa(ip->daddr);
#ifdef DEBUG
    for (i=0;i<bytes; i++) {
        if (!(i&15)) log_debug(fp, "%2X: ", i);
        log_debug(fp, "%2X ", ((unsigned char*)buf)[i]);
    }
#endif
    log_info(fp, "IPv%d:hdr-size=%d pkt-size=%d protocol=%d TTL=%d",
    ip->version, (ip->ihl)*4, ntohs(ip->tot_len), ip->protocol, ip->ttl);
    log_info(fp, "src: %s, dst: %s", src, dst);

    fflush(fp);
}

void ikev2Listener (jsonData_t* jsonData) {
	int sock;
	struct sockaddr_in addr;
	unsigned char buf[1024];
	struct protoent* proto = NULL;

	proto = getprotobyname("ICMP");
	sock = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sock < 0) {
		perror("socket");
		exit(0);
	}
	log_debug(fp, "Entering Ping Listener Loop...");
	while(1) {
		int bytes, len = sizeof(addr);
		bzero(buf, sizeof(buf));
		bytes = recvfrom(sock, buf, sizeof(buf), 0, 
				(struct sockaddr*)&addr, &len);
		if (bytes > 0)
			display(buf, bytes, jsonData);
		else {
			perror("recvfrom");
		}
	}
	exit(0);
}

void* ikev2Start(void *args) {
	pthread_t threadPID;
	char filePath[100];

	jsonData_t* jsonData = (jsonData_t*)args;

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ikev2_stats");
	fikev2Stats = fopen(filePath, "a");
	log_info(fikev2Stats, "Ikev2 started: custID: %d, server:%s", 
			jsonData->custID, jsonData->serverIP);

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ikev2_logs");
	fp = fopen(filePath, "a");
	log_info(fp, "HTTP started: custID: %d, server:%s", 
			jsonData->custID, jsonData->serverIP);

	if (pthread_create(&threadPID, NULL, ikev2Listener, jsonData)) {
		log_info(fp, "\nError creating Listener Thread"); fflush(stdout);
		exit(1);
	}
	// TBD: For now use this to ensure that the listener runs and is 
	// waiting for pkts
	while(1) {
		sleep(2); 
		continue;
	}

	fclose(fp);
	fclose(fikev2Stats);
	return 0;
}


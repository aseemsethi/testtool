/*
 * Some of the code to generate the ping packets is taken from
 * https://www.cs.utah.edu.~swalton/listings/sockets/programs/part4/chap18/myping.c
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
/* somewhat unix-specific */ 
#include <sys/time.h>
#include <unistd.h>
/* curl stuff */ 
#include <curl/curl.h>
 

FILE *fp;
FILE *fhttpStats;

void display (void *buf, int bytes, jsonData_t* jsonData) {
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

void httpListener (jsonData_t* jsonData) {
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

void* httpStart(void *args) {
	pthread_t threadPID;
	char filePath[100];

	jsonData_t* jsonData = (jsonData_t*)args;

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/http_stats");
	fhttpStats = fopen(filePath, "a");
	log_info(fhttpStats, "\n ****HTTP started: custID: %d, server:%s", 
			jsonData->custID, jsonData->serverIP);

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/http_logs");
	fp = fopen(filePath, "a");
	log_info(fp, "**  HTTP started: custID: %d, server:%s **", 
			jsonData->custID, jsonData->serverIP);

/*
	if (pthread_create(&threadPID, NULL, httpListener, jsonData)) {
		log_info(fp, "\nError creating Listener Thread"); fflush(stdout);
		exit(1);
	}
*/

	curl_main(jsonData, fhttpStats, fp);

	// TBD: For now use this to ensure that the listener runs and is 
	// waiting for pkts
	printf("\n Entering CLI loop"); fflush(stdout);
	while(1) {
		sleep(5); 
		continue;
	}

	fclose(fp);
	fclose(fhttpStats);
	return 0;
}


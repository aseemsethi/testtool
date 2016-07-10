#include <stdio.h>
#include <string.h>
#include "../common/parser.h"
#include "../common/util.h"
/* somewhat unix-specific */ 
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h> // for exit
#include "../common/log.h"
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntoa
#include <netinet/ip_icmp.h>
#include "bgp.h"
#include <fcntl.h>
#include <errno.h>

FILE *fp;
FILE *fbgpStats;
//#define PKT_DEBUG 1


bgp_t bgp;

sendBgpData (bgp_t *bgp, uchar *ptr, int length) {
    int sent;

    log_debug(fp, "BGP: SendData: Sending %d Bytes", length); fflush(stdout);
    sent = sendto(bgp->sock, ptr, length, 0,
            (struct sockaddr*)&bgp->server_addr, sizeof(bgp->server_addr));
    if(sent == -1) {
            perror(" - send error: ");
    } else {
            //log_debug(fp, " :%d Bytes", sent);
    }
    fflush(fp);
}

putBgpHdr(char *buff, int type) {
	memset(buff, 0xff, 16);
	buff[18] = type;
}

sendKeepalive (bgp_t *bgp) {
	struct bgp_open open;

	log_info(fp, "BGP: Send KEEPALIVE"); fflush(stdout);
	memset(open.bgpo_marker, 0xFF, 16);
	open.bgpo_len = htons(19);
	open.bgpo_type = BGP_KEEPALIVE;

	sendBgpData(bgp, (uchar*)&open, 19);
}

int sendUpdateWithdrawFile (bgp_t *bgp, FILE* fw) {
	struct bgp_update update;
	struct bgp_withdrawn *w;
	int i, j, len, index, totalIndex, pathAttrLen;
	jsonData_t *jsonData = bgp->jsonData;
    struct sockaddr_in addr;
	uchar buff[22];
	int val;
	char *status;

	log_info(fp, "BGP: Send UPDATE Withdraw"); fflush(stdout);
	memset(update.bgpo_marker, 0xFF, 16);
	update.bgpo_type = BGP_UPDATE;
	len = 21;  // 19 bytes fixed + 2 bytes for len of WithdrawnLen
	index = 0;

	// Read from Withdraw File
   	while (1) {
		status = fgets(buff, 20, fw);
		if (status == NULL) {
			printf("EOF recvd"); break;
		}
		val = (int)strtol(buff, (char **)NULL, 10);
		fgets(buff, 20, fw);
		printf("\n Withdraw Prefix: %d, Addr:%s", val, buff);
		if(inet_aton(buff, &addr.sin_addr)==0){
   			log_error(fp, "inet_aton() failed\n"); fflush(fp);
			printf("\n inet_aton error !!"); fflush(stdout);
   		}
		update.ext[index++] = val;
		PUT_BE32(&update.ext[index], htonl(addr.sin_addr.s_addr));
		index += 4; len += 5;
	}

	update.withdrawnLen = htons(index);

	// Len of 0 for Path Attributes
	PUT_BE16(&update.ext[index], 0);
	len +=2;
	update.bgpo_len = htons(len);

#ifdef PKT_DEBUG
	printf("\nBGP UPDATE Withdraw: Len:%d", len);
	for (i=0;i<len;i++)
		printf(" %2X", ((uchar*)&update)[i]);
#endif
	sendBgpData(bgp, (uchar*)&update, len);
	return 1;
}

sendUpdateWithdraw (bgp_t *bgp) {
	struct bgp_update update;
	struct bgp_withdrawn *w;
	int i, j, len, index, totalIndex, pathAttrLen;
	jsonData_t *jsonData = bgp->jsonData;
    struct sockaddr_in addr;
	int saveIndexForPathAttrLen = 0;
	int start = 0;
#define MAX_ROUTES 800 
	int end = MAX_ROUTES;
	int leaveLoop = 0;
	int count = jsonData->nlriRepeat;

again:
	log_info(fp, "BGP: Send UPDATE Withdraw"); fflush(stdout);
	memset(update.bgpo_marker, 0xFF, 16);
	update.bgpo_type = BGP_UPDATE;
	len = 21;  // 19 bytes fixed + 2 bytes for len of WithdrawnLen
	index = 0;

	// We repeat the 1st entry, incrementing the ip addresses till nlriCount
	printf("\nRepeating Withdrawn Routes");
	if (count <= MAX_ROUTES) {
		leaveLoop = 1; end = start + count;
	} 
   	if(inet_aton(jsonData->nlriPrefix[0], &addr.sin_addr)==0){
   		log_error(fp, "inet_aton() failed\n"); fflush(fp);
		printf("\n inet_aton error !!"); fflush(stdout);
   	}
	for(i=start;i<end;i++) {
		update.ext[index++] = jsonData->nlriLen[0];
		PUT_BE32(&update.ext[index], htonl(addr.sin_addr.s_addr)+i);
		index += 4;
		len += 5;
	}
	update.withdrawnLen = htons(index);

	// Len of 0 for Path Attributes
#include "../common/util.h"
	PUT_BE16(&update.ext[index], 0);
	len +=2;
	update.bgpo_len = htons(len);

#ifdef PKT_DEBUG
	printf("\nBGP UPDATE Withdraw: Len:%d", len);
	for (i=0;i<len;i++)
		printf(" %2X", ((uchar*)&update)[i]);
#endif
	sendBgpData(bgp, (uchar*)&update, len);
	if (leaveLoop == 1) return;

	count = count - MAX_ROUTES;
	start += MAX_ROUTES; end += MAX_ROUTES; 
	printf("  Sent: %d, Send Update for remaining: %d", end-start, count);
	{struct timespec ts;
    ts.tv_sec = 0; ts.tv_nsec = 800000000;
    nanosleep(&ts, NULL);}
	goto again;
}

sendUpdateFile (bgp_t *bgp, FILE* fu) {
	struct bgp_update update;
	struct bgp_withdrawn *w;
	int i, j, len, index, totalIndex, pathAttrLen;
	jsonData_t *jsonData = bgp->jsonData;
    struct sockaddr_in addr;
	int saveIndexForPathAttrLen = 0;
	uchar buff[22];
	int val;
	char  *status;

	log_info(fp, "BGP: Send UPDATE"); fflush(stdout);
	memset(update.bgpo_marker, 0xFF, 16);
	update.bgpo_type = BGP_UPDATE;
	len = 21;  // 19 bytes fixed + 2 bytes for len of WithdrawnLen

	index = 0;
	update.withdrawnLen = 0;

	// Now save the index of where to put in the length for Path Attributes
	saveIndexForPathAttrLen = index; // This is where pathAttrLen comes in
	index += 2;
	for (i=0;i<jsonData->pathIndex;i++) {
		update.ext[index++] = jsonData->pathFlag[i];
		update.ext[index++] = jsonData->pathType[i];
		update.ext[index++] = jsonData->pathLen[i];
		switch(jsonData->pathType[i]) {
    		struct sockaddr_in addr;
			case 1:  // ORIGIN
				update.ext[index++] = jsonData->pathValue[i];
				break;
			case 2:  // AS PATH
				break;
			case 3: // NEXT HOP
    			if(inet_aton(jsonData->pathValueNextHop[i], &addr.sin_addr)==0){
            		log_error(fp, "inet_aton() failed\n"); fflush(fp);
					printf("\n inet_aton error !!"); fflush(stdout);
    			}
				PUT_BE32(&update.ext[index], htonl(addr.sin_addr.s_addr));
				index += 4;
				break;
			default:
				printf("\n BGP UPDATE: unknown path type while building pkt");
				break;
		}
	}
	pathAttrLen = index; // This is the len of pathAttr
	PUT_BE16(&update.ext[saveIndexForPathAttrLen], pathAttrLen-2);
	len += pathAttrLen;
	
	// Read from Update File
   	while (1) {
		status = fgets(buff, 20, fu);
		if (status == NULL) {
			printf("\n EOF recvd"); break;
		}
		val = (int)strtol(buff, (char **)NULL, 10);
		fgets(buff, 20, fu);
		printf("\n Update Prefix: %d, Addr:%s", val, buff);
		if(inet_aton(buff, &addr.sin_addr)==0){
   			log_error(fp, "inet_aton() failed\n"); fflush(fp);
			printf("\n inet_aton error !!"); fflush(stdout);
   		}
		update.ext[index++] = val;
		PUT_BE32(&update.ext[index], htonl(addr.sin_addr.s_addr));
		index += 4; len += 5;
	}
	update.bgpo_len = htons(len);

#ifdef PKT_DEBUG
	printf("\nBGP UPDATE: Len:%d", len);
	for (i=0;i<len;i++)
		printf(" %2X", ((uchar*)&update)[i]);
#endif
	sendBgpData(bgp, (uchar*)&update, len);
}

sendUpdate (bgp_t *bgp) {
	struct bgp_update update;
	struct bgp_withdrawn *w;
	int i, j, len, index, totalIndex, pathAttrLen;
	jsonData_t *jsonData = bgp->jsonData;
    struct sockaddr_in addr;
	int saveIndexForPathAttrLen = 0;
	int start = 0;
#define MAX_ROUTES 800 
	int end = MAX_ROUTES;
	int leaveLoop = 0;
	int count = jsonData->nlriRepeat;

again:
	log_info(fp, "BGP: Send UPDATE"); fflush(stdout);
	memset(update.bgpo_marker, 0xFF, 16);
	update.bgpo_type = BGP_UPDATE;
	len = 21;  // 19 bytes fixed + 2 bytes for len of WithdrawnLen

	index = 0;
	totalIndex = 0;
	for (j=0;j<jsonData->wIndex;j++) {
    	struct sockaddr_in addr;
		w = ( struct bgp_withdrawn *)(update.ext + totalIndex);
		w->withdrawnPrefix = jsonData->withdrawnPrefix[j];
		index = w->withdrawnPrefix/8;
    	if(inet_aton(jsonData->withdrawnRoute[j], &addr.sin_addr)==0){
          	log_error(fp, "inet_aton() failed\n"); fflush(fp);
			printf("\n inet_aton error !!"); fflush(stdout);
    	}
		//log_info(fp, "BGP withdrawRoute= %x", htonl(addr.sin_addr.s_addr));
		for (i=0; i<index; i++) {
			w->withdrawnRoute[i]=(htonl(addr.sin_addr.s_addr)>>(8*(3-i)))&0xFF;
		}
		index += 1; // 1 for length of withdrawnPrefix
		totalIndex += index;
	}
	len += totalIndex;  // sum up all Withdrawn Routes
	update.withdrawnLen = htons(totalIndex);

	index = totalIndex;
	// Now save the index of where to put in the length for Path Attributes
#include "../common/util.h"
	saveIndexForPathAttrLen = index; // This is where pathAttrLen comes in
	index += 2;
	for (i=0;i<jsonData->pathIndex;i++) {
		update.ext[index++] = jsonData->pathFlag[i];
		update.ext[index++] = jsonData->pathType[i];
		update.ext[index++] = jsonData->pathLen[i];
		switch(jsonData->pathType[i]) {
    		struct sockaddr_in addr;
			case 1:  // ORIGIN
				update.ext[index++] = jsonData->pathValue[i];
				break;
			case 2:  // AS PATH
				break;
			case 3: // NEXT HOP
    			if(inet_aton(jsonData->pathValueNextHop[i], &addr.sin_addr)==0){
            		log_error(fp, "inet_aton() failed\n"); fflush(fp);
					printf("\n inet_aton error !!"); fflush(stdout);
    			}
				//log_info(fp, "BGP PathAttr NextHop= %x", addr.sin_addr.s_addr);
				PUT_BE32(&update.ext[index], htonl(addr.sin_addr.s_addr));
				index += 4;
				break;
			default:
				printf("\n BGP UPDATE: unknown path type while building pkt");
				break;
		}
	}
	pathAttrLen = index - totalIndex; // This is the len of pathAttr
	PUT_BE16(&update.ext[saveIndexForPathAttrLen], pathAttrLen-2);
	len += pathAttrLen;

	for(i=0;i<jsonData->nIndex;i++) {
		update.ext[index++] = jsonData->nlriLen[i];
    	if(inet_aton(jsonData->nlriPrefix[i], &addr.sin_addr)==0){
       		log_error(fp, "inet_aton() failed\n"); fflush(fp);
			printf("\n inet_aton error !!"); fflush(stdout);
    	}
		//log_info(fp, "BGP NLRI = %x", addr.sin_addr.s_addr);
		PUT_BE32(&update.ext[index], htonl(addr.sin_addr.s_addr));
		index += 4;
		len += 5;
	}
	// We repeat the 1st entry, incrementing the ip addresses till nlriCount
	printf("\nRepeating NLRI");
	if (count <= MAX_ROUTES) {
		leaveLoop = 1; end = start + count;
	} 
	for(i=start;i<end;i++) {
		update.ext[index++] = jsonData->nlriLen[0];
		PUT_BE32(&update.ext[index], htonl(addr.sin_addr.s_addr)+i);
		index += 4;
		len += 5;
	}
	update.bgpo_len = htons(len);

#ifdef PKT_DEBUG
	printf("\nBGP UPDATE: Len:%d", len);
	for (i=0;i<len;i++)
		printf(" %2X", ((uchar*)&update)[i]);
#endif
	sendBgpData(bgp, (uchar*)&update, len);
	if (leaveLoop == 1) return;

	count = count - MAX_ROUTES;
	start += MAX_ROUTES; end += MAX_ROUTES; 
	printf("  Sent: %d, Send Update for remaining: %d", end-start, count);
	if (jsonData->nlriRepeatDelay != 0) {
		printf("\n Sleeping for %d seconds, between 800 route updates",
				jsonData->nlriRepeatDelay); fflush(stdout);
		sleep(jsonData->nlriRepeatDelay);
	} else {	
		struct timespec ts;
    	ts.tv_sec = 0; ts.tv_nsec = 800000000;
    	nanosleep(&ts, NULL);
	}
	goto again;
}

sendOpen (bgp_t *bgp) {
	struct bgp_open open;
	int i;
	jsonData_t *jsonData = bgp->jsonData;

	log_info(fp, "BGP: Send OPEN"); fflush(stdout);
	memset(open.bgpo_marker, 0xFF, 16);
	open.bgpo_len = htons(29);
	open.bgpo_type = BGP_OPEN;
	open.bgpo_version = jsonData->version; // BGP_VERSION;
	open.bgpo_myas = htons(jsonData->myas);
	open.bgpo_holdtime = 0;

    if(inet_aton(jsonData->routerID, &bgp->routerID.sin_addr) == 0) {
		log_error(fp, "BGP: inet_aton failed");
		exit(1);
	}
	log_info(fp, "BGP self router ID = %x", bgp->routerID.sin_addr.s_addr);
	open.bgpo_id = bgp->routerID.sin_addr.s_addr;
	open.bgpo_optlen = 0;

	//for (i=0;i<29;i++)
	//	printf(" %2X", ((uchar*)&open)[i]);
	sendBgpData(bgp, (uchar*)&open, 29);
}

bgpPrintConfig(bgp_t *bgp) {
	jsonData_t *jsonData = bgp->jsonData;
	int i;

	log_info(fp, "BGP Version= %d", jsonData->version);
	log_info(fp, "My AS= %d", jsonData->myas);
	// Send Update Message
	log_info(fp, "Withdrawn len = %d", jsonData->withdrawnLen);
	for(i=0;i<jsonData->wIndex;i++) {
		log_info(fp, "Withdrawn prefix:%d, route:%s", 
			jsonData->withdrawnPrefix[i], jsonData->withdrawnRoute[i]);
	}
	log_info(fp, "Path Attr len = %d", jsonData->pathAttrLen);
	for(i=0;i<jsonData->pathIndex;i++) {
		switch(jsonData->pathType[i]) {
    	struct sockaddr_in addr;
		case 1:  // ORIGIN
			log_info(fp, "Path Attributes: Flag:%d, Type:%d, Len:%d, Val:%d",
			jsonData->pathFlag[i], jsonData->pathType[i], 
			jsonData->pathLen[i], jsonData->pathValue[i]);
			break;
		case 2:  // AS PATH
			log_info(fp, "\n Path Attributes: Flag:%d, Type:%d, Len:%d",
			jsonData->pathFlag[i], jsonData->pathType[i], 
			jsonData->pathLen[i]);
			break;
		case 3: // NEXT HOP
			log_info(fp, "Path Attributes: Flag:%d, Type:%d, Len:%d",
			jsonData->pathFlag[i], jsonData->pathType[i], 
			jsonData->pathLen[i]);
    		if(inet_aton(jsonData->pathValueNextHop[i], &addr.sin_addr)==0){
           		log_error(fp, "inet_aton() failed\n"); fflush(fp);
				log_info(fp, "BGP inet_aton error !!"); fflush(stdout);
    		}
			log_info(fp, ", BGP PathAttr NextHop= %x", addr.sin_addr.s_addr);
			break;
		default:
			log_info(fp, "Unknown Path Attribute: %d", jsonData->pathType[i]);
			break;
		}
	}
	for(i=0;i<jsonData->nIndex;i++) {
		log_info(fp, "NLRI Routes:%d, route:%s", 
			jsonData->nlriLen[i], jsonData->nlriPrefix[i]);
	}
	log_info(fp, "Repeat NLRI Routes:%d", jsonData->nlriRepeat);
	log_info(fp, "Repeat NLRI Routes with Delay:%d", jsonData->nlriRepeatDelay);
	fflush(stdout);
}

initBgpConnection(bgp_t *bgp, jsonData_t* jsonData) {
    struct sockaddr_in;
	int arg, err;

    if((bgp->sock=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket:");
            log_error(fp, "BGP ERROR: create creation socket"); fflush(fp);
            exit(1);
    }
    bgp->server_addr.sin_family = AF_INET;
    bgp->server_addr.sin_port = htons(BGP_TCP_PORT);
    if(inet_aton(jsonData->serverIP, &bgp->server_addr.sin_addr) == 0) {
            log_error(fp, "inet_aton() failed\n");
            log_error(fp, "BGP ERROR: create in inet_aton"); fflush(fp);
    }
    log_info(fp, "BGP: Connect to %s", jsonData->serverIP); fflush(fp);
	// Set non-blocking 
	if( (arg = fcntl(bgp->sock, F_GETFL, NULL)) < 0) { 
		perror("F_GETFL:");
		exit(0); 
	} 
	arg |= O_NONBLOCK; 
	if( fcntl(bgp->sock, F_SETFL, arg) < 0) { 
		perror("F_SETFL:");
		exit(0); 
	} 
    err = connect(bgp->sock, (struct sockaddr *)&bgp->server_addr,
                sizeof(struct sockaddr));
	if (errno != EINPROGRESS) {
		// Note: connect on blocking socket returns EINPROGRESS
        log_error(fp, "BGP ERROR: create connecting to server"); fflush(fp);
        log_error(fbgpStats, "BGP ERROR: create connecting to server");
        fflush(fbgpStats);
        perror("Connect Error:");
        exit(1);
    } else {
		/* struct timeval stTv;
		fd_set write_fd; stTv.tv_sec = 20; stTv.tv_usec = 0;
        FD_ZERO(&write_fd); FD_SET(bgp->sock,&write_fd);
        select((bgp->sock+1), NULL, &write_fd, NULL, &stTv);
		*/
//http://stackoverflow.com/questions/10187347/async-connect-and-disconnect-with-epoll-linux/10194883#10194883
		int result;
		socklen_t result_len = sizeof(result);
		if (getsockopt(bgp->sock, SOL_SOCKET, SO_ERROR, 
				&result, &result_len) < 0) {
			// error, fail somehow, close socket
			return;
		}
		if (result != 0) {
			// connection failed; error code is in 'result'
			return;
		}
		// socket is ready for read()/write()
		//log_info(fp, "TCP Connected.."); fflush(fp);
	}
    log_info(fp, "BGP TCP connection created to %s, sock:%d",
        jsonData->serverIP, bgp->sock);
    fflush(fp);
}

void *bgpListener(bgp_t* bgp) {
	int running = 1;
	int countUpdates=0;

	log_info(fp, "BGP Listener: started"); fflush(fp);
	while(running){
		struct timeval selTimeout;
		selTimeout.tv_sec = 5;       /* timeout (secs.) */
		selTimeout.tv_usec = 0;
		fd_set readSet;
		FD_ZERO(&readSet);
		char* p;
		int count;
		FD_SET(bgp->sock, &readSet);
		const u_char marker[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		};

		int numReady = select(FD_SETSIZE, &readSet, NULL, NULL, &selTimeout);
		if(numReady > 0){
			if (FD_ISSET (bgp->sock, &readSet)) {
				//printf("\n BGP Data recvd...");
			}
			char buffer[1000] = {'\0'};
			int i;
			int bytesRead = read(bgp->sock, &buffer, sizeof(buffer));
			if(bytesRead < 0) {
				perror("\nBytesRead < 0, Shutdown:"); fflush(stdout);
				running = 0;
			} else if (bytesRead == 0) {
			// TBD: For some reason, the select returns immediately and 
			// ignores the timeout, even though the sock is in NONBLOCK
			// mode. For now, ignoring this and continuing.
				continue;
			}
#ifdef PKT_DEBUG
			printf("\nBytesRead %i", bytesRead);
			for (i=0;i<bytesRead;i++)
				printf(" %2X", buffer[i]);
			fflush(stdout);
#endif
			p = &buffer[0];
			count = 0;
			// Search for the marker
			while (1) {
				if (memcmp(p, marker, sizeof(marker)) != 0) {
					printf("."); p++; fflush(stdout);
				} else {
					printf("\n Marker Found"); break;
				}
				if (count++ > bytesRead) break;
			}
			switch (buffer[18]) {
				case 1: log_info(fp, "OPEN recvd"); 
						sendOpen(bgp);
						sendKeepalive(bgp); 
						break;
				case 2: 
						log_info(fp, "UPDATE recvd");
						sendUpdate(bgp);
						if (bgp->jsonData->repeatUpdate != 0) {
							countUpdates = bgp->jsonData->repeatUpdate;
							for (i=0;i<countUpdates;i++) {	
								sleep (3);
								sendUpdate(bgp); //advertise
								sleep (3);
								sendUpdateWithdraw(bgp); //withdraw
							}
						}
						break;
				case 3: log_info(fp, "NOTIFICATION recvd"); break;
				case 4: log_info(fp, "KEEPALIVE recvd"); break;
				default: 
					log_info(fp, "Unknown BGP Type recvd: %d",
					buffer[18]);
			}
			fflush(fp);
		}
	}
	log_error(fp, "\nBGP Listener: stopped"); fflush(stdout);
}

int bgp_main(jsonData_t *jsonData, FILE *stats, FILE *logs) {
	pthread_t threadPID;

	fp = logs;
	fbgpStats = stats;
	log_info(fp, "BGP started..."); fflush(fp);

	bgp.jsonData = jsonData;
	bgpPrintConfig(&bgp);
	initBgpConnection(&bgp, jsonData);
	if (pthread_create(&threadPID, NULL, bgpListener, &bgp)) {
		log_info(fp, "Error creating BGP Listener Thread"); fflush(stdout);
		exit(1);
	}
	//sendUpdateWithdraw(&bgp); //withdraw
	// while (1) sleep(2);
}

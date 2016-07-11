#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntoa
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include "../common/parser.h"
#include "../common/util.h"
#include "ssl.h"
#include "../common/log.h"

sslStruct sslP;
param_t param;
FILE *fp;

sendData(sslStruct *sslP, uchar *ptr, int length) {
    int sent;

    log_debug(fp, "SSL: SendData: Sending %d Bytes", length); fflush(stdout);
    sent = sendto(sslP->sock, ptr, length, 0,
            (struct sockaddr*)&sslP->server_addr, sizeof(sslP->server_addr));
    if(sent == -1) {
            perror(" - send error: ");
    } else {
            log_debug(fp, " :%d Bytes", sent);
    }
    fflush(fp);
}

/*
 *  * Set up a INET socket and connect to SERVER on SSL_PORT
 *   * SSL_PORT = 443 for real SSL servers
 *    */
initConnectionToServer(sslStruct *sslP, jsonData_t* jsonData) {
    struct sockaddr_in;

    if((sslP->sock=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket:");
			log_error(fp, "SSL ERROR: create creation socket"); fflush(fp);
            exit(1);
    }
    sslP->server_addr.sin_family = AF_INET;
    sslP->server_addr.sin_port = htons(jsonData->sslPort);
    if(inet_aton(jsonData->serverIP, &sslP->server_addr.sin_addr) == 0) {
            log_error(fp, "inet_aton() failed\n");
			log_error(fp, "SSL ERROR: create in inet_aton"); fflush(fp);
    }
	log_info(fp, "SSL: Connect to %s", jsonData->serverIP);
    if(connect(sslP->sock, (struct sockaddr *)&sslP->server_addr,
                sizeof(struct sockaddr)) == -1) {
		log_error(fp, "SSL ERROR: create connecting to server"); fflush(fp);
		log_error(sslP->fsslStats, "SSL ERROR: create connecting to server");
		fflush(sslP->fsslStats); 
        perror("Connect");
        exit(1);
    }
    log_info(fp, "TCP connection created to %s, sock:%d", 
		jsonData->serverIP, sslP->sock);
	fflush(stdout);
}

int getSelfIP() {
	int fd, status;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		log_error(fp, "ERROR: create scck for interface IP"); fflush(fp);
		return -1;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
		perror("\nioctl failure");
		return -1;
	}
	close(fd);

	sprintf(sslP.selfIP, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	log_info(fp, "SSL: SelfIP: %s", sslP.selfIP);
	fflush(fp);

	return 0;
}

/*
 * Check for:
 *  - cert identity matching domain name
 *  - cert is within validity perios
 *  - digital sig is valid
 */
verifyCertificate(sslStruct *sslP) {
	uchar *buff, *subj, *issuer;
	int version;
	const uchar *ptr, *tmpPtr;
	const uchar *data;
	size_t len, msgLen, totalCertLen, serverCertLen;
	size_t parsedLen = 0;
	size_t verifyCertLen;
	int count = 0;

#define CERT_LEN_INDEX 1
	// buff[0] points to Handshake Type - certificate
	buff = sslP->paramP->buff;
	len = sslP->paramP->buffLen;
	msgLen = GET_BE16(&buff[CERT_LEN_INDEX+1]);
	totalCertLen = GET_BE16(&buff[CERT_LEN_INDEX+1+3]);
	serverCertLen = GET_BE16(&buff[CERT_LEN_INDEX+1+3+3]);
	log_info(fp, "\n Pkg Len = %d, Total Cert Len = %d", msgLen, totalCertLen);
    log_info(fp, "\n Server Certificate verification, Len: %d", serverCertLen);
	// Parse the Server Cert
	ptr = &buff[10];
	X509 *cert = d2i_X509(NULL, &ptr, serverCertLen);	
	if (cert == NULL) {
		log_info(fp, "\n d2i_X509 returns NULL for Cert verification");
		return -1;
	}
	log_info(fp, "\n.........Server Certificate........................");
	subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	version = ((int)X509_get_version(cert)) + 1; // 0 indexed
	log_info(fp, "\nSubject: %s, \nIssuer: %s, \n Version: %d", 
		subj, issuer, version);
	// Get Public Key Algorith Name
	int pkey = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
	if (pkey == NID_undef) {
		log_info (fp, "\n Cert Verify: unable to find signature algo");
		goto clean;
	}
	char sigalgo[100];
	const char * sslbuf = OBJ_nid2ln(pkey);
	if (strlen(sslbuf) > 100) {
		log_info (fp, "\n Cert Verify: len is greater than allocated");
		goto clean;
	}
	strncpy(sigalgo, sslbuf, 100);
	log_info(fp, ", Public Key Algorithm Algorithm: %s", sigalgo);
	EVP_PKEY *public_key = X509_get_pubkey(cert);
	if (pkey == NID_rsaEncryption) {
		if (public_key == NULL) {
			log_info(fp, "\nunable to get public key from certificate");
			return -1;
		}
		char *rsa_e_dec, *rsa_n_hex;
		sslP->paramP->rsa_key = public_key->pkey.rsa;
		// Both the following are printable strings and need to be freed 
		// by caling OPENSSL_free()
		rsa_e_dec = BN_bn2dec(sslP->paramP->rsa_key->e); // RSA Exponent
		rsa_n_hex = BN_bn2hex(sslP->paramP->rsa_key->n); // RSA Modulus
		log_info(fp, "\n RSA Exponent = %s, \n RSA Modulus = %s", rsa_e_dec, rsa_n_hex);
	}
	EVP_PKEY_free(public_key);
clean:
	OPENSSL_free(subj); 
	OPENSSL_free(issuer); 

	// Parse the Server Cert Chain
	ptr = &buff[10+serverCertLen]; // Set ptr to point to next Cert Len field
	parsedLen = serverCertLen+3;
	tmpPtr = ptr+3;
	while (parsedLen < totalCertLen) {
		log_info(fp, "\n.........Server Certificate Chain %d.............", count++);
		//printf("\n Len: Parsed: %d, Total: %d", parsedLen, totalCertLen);
		verifyCertLen = GET_BE16(&ptr[1]);
		log_info(fp, "\nCert Chain Len: %d", verifyCertLen);
		X509 *cert = d2i_X509(NULL, &tmpPtr, serverCertLen);	
		if (cert == NULL) {
			log_info(fp, "\n d2i_X509 returns NULL for Cert verification chain");
			return -1;
		}
		subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		log_info(fp, "\nSubject: %s", subj);
		OPENSSL_free(subj); 
		ptr += verifyCertLen + 3; // Set ptr to point to next Cert Len field
		tmpPtr = ptr+3;
		parsedLen += verifyCertLen+3;
	} // End parsing Cert Chain
	log_info(fp, "\n..................................................");
}


recvCertificate (sslStruct *sslP) {
    int status;

    // Get the packet bytes and save to handshakeMsgs
    // buff[0] points to Handshake Type - ServerHello
    memcpy(&(sslP->paramP->clientHandshakeMsgs[sslP->paramP->clientHandshakeMsgsIndex]),
        &(sslP->paramP->buff[0]), sslP->paramP->buffLen);
    sslP->paramP->clientHandshakeMsgsIndex += sslP->paramP->buffLen;
    log_info(fp, "\n Certificate saved bytes: %d", sslP->paramP->buffLen);

    status = verifyCertificate(sslP);
    if (status == -1) {
        log_info(fp, "\n Certificate verification failed");
        return -1;
    }
	log_info(fp, "\n Certificate verification passed"); fflush (stdout);
    return 0;
}

int recvServerHelloDone(sslStruct *sslP) {
    // Get the packet bytes and save to handshakeMsgs
    // buff[0] points to Handshake Type - ServerHello
    memcpy(&(sslP->paramP->clientHandshakeMsgs[sslP->paramP->clientHandshakeMsgsIndex]),
        &(sslP->paramP->buff[0]), sslP->paramP->buffLen);
    sslP->paramP->clientHandshakeMsgsIndex += sslP->paramP->buffLen;
    log_info(fp, "\n ServerHelloDone saved bytes: %d", sslP->paramP->buffLen);
}

recvServerHello (sslStruct *sslP) {
    int i;
        
    // Get the packet bytes and save to handshakeMsgs
    // buff[0] points to Handshake Type - ServerHello
    memcpy(&(sslP->paramP->clientHandshakeMsgs[sslP->paramP->clientHandshakeMsgsIndex]),
        &(sslP->paramP->buff[0]), sslP->paramP->buffLen);
    sslP->paramP->clientHandshakeMsgsIndex += sslP->paramP->buffLen;
    log_info(fp, "\n ServerHello saved bytes: %d", sslP->paramP->buffLen);
        
    // Get the random value from the packet for master secret
    // buff[0] points to Handshake Type - ServerHello
    // random bytes start from index 6 (including time stamp)
    memcpy(&(sslP->paramP->serverRandom[0]), &(sslP->paramP->buff[6]), 32);
	/*
    log_info(fp, "\n Server Random recvd: ");
    for(i = 0; i <32; i++)
        log_info(fp, "%x ", sslP->paramP->serverRandom[i]);
	*/
}       

// buff[0] points to Alert Message, i.e. Level and Description
recvAlert (sslStruct *sslP) {
	uchar *buff;

	buff = sslP->paramP->buff;
	log_info(fp, "\n Alert !!"); fflush(stdout);
	if (buff[0] == 1) log_info(fp, " WARNING:");
	if (buff[0] == 2) log_info(fp, " FATAL:");
	// save the ALERT Code for the sslTestExec to check.
	sslP->paramP->verifyAlertCode = buff[1]; 
	switch (buff[1]) {
	case SSL3_AD_CLOSE_NOTIFY: //                   0      
		log_info(fp, " SSL3_AD_CLOSE_NOTIFY"); break;
	case SSL3_AD_UNEXPECTED_MESSAGE: //            10     
		log_info(fp, " SSL3_AD_UNEXPECTED_MESSAGE"); break;
	case SSL3_AD_BAD_RECORD_MAC: //                20    
		log_info(fp, " SSL3_AD_BAD_RECORD_MAC"); break;
	case TLS1_AD_DECRYPTION_FAILED: //             21   
		log_info(fp, " TLS1_AD_DECRYPTION_FAILED"); break;
	case TLS1_AD_RECORD_OVERFLOW: //               22  
		log_info(fp, " TLS1_AD_RECORD_OVERFLOW"); break;
	case SSL3_AD_DECOMPRESSION_FAILURE: //         30 
		log_info(fp, " SSL3_AD_DECOMPRESSION_FAILURE"); break;
	case SSL3_AD_HANDSHAKE_FAILURE: //             40
		log_info(fp, " SSL3_AD_HANDSHAKE_FAILURE"); break;
	case SSL3_AD_NO_CERTIFICATE: //                41      
		log_info(fp, " SSL3_AD_NO_CERTIFICATE"); break;
	case SSL3_AD_BAD_CERTIFICATE: //               42     
		log_info(fp, " SSL3_AD_BAD_CERTIFICATE"); break;
	case SSL3_AD_UNSUPPORTED_CERTIFICATE: //       43    
		log_info(fp, " SSL3_AD_UNSUPPORTED_CERTIFICATE"); break;
	case SSL3_AD_CERTIFICATE_REVOKED: //           44   
		log_info(fp, " SSL3_AD_CERTIFICATE_REVOKED"); break;
	case SSL3_AD_CERTIFICATE_EXPIRED: //           45  
		log_info(fp, " SSL3_AD_CERTIFICATE_EXPIRED"); break;
	case SSL3_AD_CERTIFICATE_UNKNOWN: //           46 
		log_info(fp, " SSL3_AD_CERTIFICATE_UNKNOWN"); break;
	case SSL3_AD_ILLEGAL_PARAMETER: //             47      
		log_info(fp, " SSL3_AD_ILLEGAL_PARAMETER"); break;
	case TLS1_AD_UNKNOWN_CA: //                    48     
		log_info(fp, " TLS1_AD_UNKNOWN_CA"); break;
	case TLS1_AD_ACCESS_DENIED: //                 49    
		log_info(fp, " TLS1_AD_ACCESS_DENIED"); break;
	case TLS1_AD_DECODE_ERROR: //                  50   
		log_info(fp, " TLS1_AD_DECODE_ERROR"); break;
	case TLS1_AD_DECRYPT_ERROR: //                 51  
		log_info(fp, " TLS1_AD_DECRYPT_ERROR"); break;
	case TLS1_AD_EXPORT_RESTRICTION: //            60 
		log_info(fp, " TLS1_AD_EXPORT_RESTRICTION"); break;
	case TLS1_AD_PROTOCOL_VERSION: //              70     
		log_info(fp, " TLS1_AD_PROTOCOL_VERSION"); break;
	case TLS1_AD_INSUFFICIENT_SECURITY: //         71    
		log_info(fp, " TLS1_AD_INSUFFICIENT_SECURITY"); break;
	case TLS1_AD_INTERNAL_ERROR: //                80   
		log_info(fp, " TLS1_AD_INTERNAL_ERROR"); break;
	case TLS1_AD_USER_CANCELLED: //                90  
		log_info(fp, " TLS1_AD_USER_CANCELLED"); break;
	case TLS1_AD_NO_RENEGOTIATION: //             100 
		log_info(fp, " TLS1_AD_NO_RENEGOTIATION"); break;
	default:
		log_info(fp,"  UNKNOWN CODE: %d", buff[1]); break;
		
	}
}

/*
 * This is the start of the recvThread. Runs parallel to the main thread
 * Never returns
 * Stays in a select loop
 * 	Receives packets from network
 * 	Invokes the sslFSM[state][event]
 */
void* recvFunction(void *arg) {
	sslStruct *sslP = (sslStruct*)arg;
	uchar buff[5000];  // uchar is important
	int bytes_recv, index, i;
	int set = 0;
	int remBytes = 0;
	ushort RecordHdrLengthRecvd = 0;
	FILE *fp = sslP->fp;

	/* Notes on SSL Length
 	 * 1st Byte      2nd Byte    3rd Byte 
 	 * # S Length    Length      Padding Length
 	 * # - number of bytes in header. 0 indicates 3 byte hdr. 1 a 2 byte header
 	 * S - security escape, not implemented 
 	 * Example: For "Certificate" pkt sent by Server:
 	 * Outer Hdr Len: 12 91
 	 * Inner Hdr Len: 00 12 8d
 	 */

	log_info(fp, "SSL: recvFunction thread created"); fflush(fp);
	while(1) {
		bytes_recv = recv(sslP->sock,&buff[0], 5, MSG_PEEK);
		//log_debug(fp, " bytes_recv = %d, ", bytes_recv);
        if (bytes_recv == -1) { perror("-1: Error during recv: "); exit(1); }
        if (bytes_recv == 0) { 
				log_error(fp, "SSL: Error: recvFunction: sock closed in recv, bytes_Recv = 0"); fflush(fp);
				sleep(10); // This is so that sslTestsExec has time 
							//to gather stats
				exit(1); // No point keeping this since the sock is gone
		}
		switch(buff[0]) {
		case change_cipher_spec:
                log_info(fp, "	<- SSL: Change Cipher"); break;
		case alert:
                log_info(fp, "	<- SSL: Alert"); break;
		case handshake:
                log_info(fp, "	<- SSL: Handshake"); break;
		case application_data:
                log_info(fp, "	<- SSL: App data"); break;
		default:
                log_error(fp, "	<- SSL: Error pkt recvd: %d, ", buff[0]);
				// We have some junk data. Throw it away
	 		   i=recv(sslP->sock,&buff[0],5000, 0);
				log_info(fp, "..discarding %d len data\n", i); continue;
		}
        log_info(fp, "  Version: %d, %d", buff[1], buff[2]);
	    sslP->paramP->versionResp[0] = buff[1];
       	sslP->paramP->versionResp[1] = buff[2];
		buff[3] = buff[3] & 0x7F; // clears the MSB # flag in MSByte
        RecordHdrLengthRecvd = GET_BE16(&buff[3]);
        //printf("  Record Hdr Length: %d", RecordHdrLengthRecvd);
		i=recv(sslP->sock,&buff[0],
				RecordHdrLengthRecvd+RECORD_HDR_LEN,MSG_WAITALL);
        //printf("  recvd %d\n", i);
		index = RECORD_HDR_LEN;

		sslP->paramP->buff = &buff[index];
		sslP->paramP->buffLen = RecordHdrLengthRecvd;
		if (buff[0] == change_cipher_spec) { continue; }
		if (buff[0] == alert) { recvAlert(sslP); continue; }

		switch(buff[index]) {
        case hello_request:
                log_info(fp, "  	<- Handshake Type: Hello Request"); break;
        case client_hello:
                log_info(fp, "  	<- Handshake Type: Client Hello"); break;
        case server_hello:
                log_info(fp, "  	<- Handshake Type:  Server Hello");
                set = 0x01<<(server_hello);
                sslP->paramP->handshakeResp |= set;
				recvServerHello(sslP);
				break;
        case certificate:
                log_info(fp, "  	<- Handshake Type: Certificate");
                set = 0x01<<(certificate);
                sslP->paramP->handshakeResp |= set;
				recvCertificate (sslP);
                break;
        case server_key_exchange:
                log_info(fp, "  	<- Handshake Type: Server Key Exchange");
                set = 0x01<<(server_key_exchange);
                sslP->paramP->handshakeResp |= set;
                break;
        case certificate_request:
                log_info(fp, "  	<- Handshake Type: Certificate Request");
                set = 0x01<<(certificate_request);
                sslP->paramP->handshakeResp |= set;
                break;
        case server_hello_done:
                log_info(fp, "  	<- Handshake Type:  Server Hello Done");
                set = 0x01<<(server_hello_done);
                sslP->paramP->handshakeResp |= set;
				recvServerHelloDone(sslP);
                break;
        case certificate_verify:
                log_info(fp, "  	<- Handshake Type: Certificate Verify"); break;
                break;
        case client_key_exchange:
                log_info(fp, "  	<- Handshake Type: Client Key Exchange"); break;
                break;
        case finished:
                log_info(fp, "  	<- Handshake Type: Finished");
                set = 0x01<<(finished);
                sslP->paramP->handshakeResp |= set;
                break;
		default:
                log_info(fp, "  		<- Handshake Type: Unknown");
		} // end switch()
		fflush(fp);
	}

}

void* sslStart(void *args) {
	jsonData_t* jsonData = (jsonData_t*)args;
	char filePath[100];

	if (pthread_mutex_init(&sslP.lock, NULL) != 0) {
		printf("\nMutex init failed\n"); fflush(stdout);
		perror("SSL Error:");
		fflush(stdout);
		return 0;
	} 
	// ssl_logs
	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ssl_logs");
	fp = fopen(filePath, "a");

	// ssl_stats
	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ssl_stats");
	sslP.fsslStats = fopen(filePath, "a");

	fprintf(fp, "\nSSL started"); fflush(fp);
    getSelfIP();
	sslP.paramP = &param;
	sslP.fp = fp;
	sslTestsExec(&sslP, jsonData);

	while(1) {
		sleep(2);
		continue;
	}
	fclose(fp);
	fflush(stdout);
	return 0;
}

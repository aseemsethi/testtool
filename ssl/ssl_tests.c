#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntoa
#include <linux/if_packet.h> //sll
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include "../common/parser.h"
#include <sys/signal.h>
#include "ssl.h"
#include "../common/log.h"
#include "../common/util.h"

#define PASS 1
#define FAIL 0
#define SSL_NUM_TESTS 7


FILE *fp;
void* recvFunction(void *arg);

typedef struct {
	char cveId[30];
	// 1st packet exchange
	int (*init_params)(sslStruct *ssl, param_t *args);
	int (*send)(sslStruct *ssl, param_t *args);
	int (*verify)(sslStruct *ssl, param_t *args, int pkt, int verifyAlertCode);
	// verifyPassed - needs to get this pkt to pass, 
	// verifyFailied - should not get this pkt
	int firstRecvdPkt; 
	// if verifyFailed, then if this AlertCode is set to non INVALID, the ALERT
	// recvd should match this code, else test fails
	int verifyAlertCode;
	int (*update_stats)(sslStruct *ssl, param_t *args, char* details);
	
	// 2nd packet exchange
	int (*send_again)(sslStruct *ssl, param_t *args);
	int (*verify_again)(sslStruct *ssl, param_t *args, int pkt, int verifyAlertCode);
	// if verify_again is set to verifyFailed, then if this AlertCode is set to 
	// non INVALID, the secondRecvdPkt should NOT match, else test fails
	int secondRecvdPkt;
	char details[240];
} sslTests_t;


typedef struct {
	char cveId[20];
	int  result;
} sslTestsResults_t;

sslTestsResults_t sslTestsResults[SSL_NUM_TESTS];


encrypt (sslStruct *sslP, char *buff, char *encryptedBuf, int len) {
    int padding = RSA_PKCS1_PADDING;
    int result;

    // The encrypted bufer must be of size RSA_size(rsa_key)
    log_info(fp, "\nRSA Size = %d", RSA_size(sslP->paramP->rsa_key));
    result = RSA_public_encrypt(len, buff, encryptedBuf,
                sslP->paramP->rsa_key, padding);
    return result;
}

char* msgToString(int msg) {
    switch (msg) {
    case hello_request: return "hello_req";
    case client_hello: return "client_hello";
    case server_hello: return "server_hello";
    case certificate: return "certificate";
    case server_key_exchange: return "server_key_xchange";
    case certificate_request: return "certificate_req";
    case server_hello_done: return "server_hello_done";
    case certificate_verify: return "server_verify";
    case client_key_exchange: return "client_key_xchange";
    case finished: return "finished";
    }
}

logRecvdPkts(sslStruct *sslP) {
	int i;
    for (i=0;i<32;i++) {
        if (sslP->paramP->handshakeResp & (1<<i)) {
            log_info(fp, "%s ", msgToString(i)); fflush(fp);
        }
    }
}


sendClientFinished(sslStruct *sslP, param_t *args) {
	uchar buff[1024];
	uchar plainText[256];
	uchar verifyData[256];
	uchar *p = &buff[0];
	ushort length = 0;
	struct timeval tv;
	time_t curtime;
	uchar digest[16];
	uchar sha1Hash[20];
	int result;
	int i;

	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	p[1] = SSL_VERSION_1;
	p[2] = SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = finished; // 20
	p[6] = 0;  // 3rd MSByte of the Length, usualy 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	// Calculate Master Secret
	// TLS1.0+
	// Function call - tls1_prf()
	// master_secret = PRF(pre_master_secret, "master secret", 
	// 				ClientHello.random + ServerHello.random)
	// Note: randoms are 32 bytes (include the timestamps)
	// sslC->masterSecret = PRF (sslC->preMasterSecret, "master secret", 
	// sslC->random, sslC->serverRandom)
	
	// SSLv3
	// Function call - ssl3_generate_master_secret()
	// master_secret = 
	// 	MD5(pre_master_secret + SHA1('A' + pre_master_secret + randbytes)) +
	// 	MD5(pre_master_secret + SHA1('BB' + pre_master_secret + randbytes)) +
	// 	MD5(pre_master_secret + SHA1('CCC' + pre_master_secret + randbytes)) +
	//
	// 	Function ssl3_generate_master_secret taken from ssl/s3_enc.c called from
	// 	ssl/s3_clnt.c during sending of CLIENT_KEY_EXCHANGE pkt to server via
	// 	the vector generate_master_secret()
	//
	{
	uchar n, dest[48];
	n = ssl3_generate_master_secret(sslP,
		dest, sslP->paramP->preMasterSecret, 48);
	printf("Len of Key Block = %d", n);
	memcpy(sslP->paramP->masterSecret, dest, 48);
	};
	
	// Calculate verify_data for Finished Msg - for SSLv3
	// Sender: client = 0x434C4E54; server = 0x53525652
	// md5_hash[16] = MD5(masterSecret + pad2 + 
	// 			      MD5(handshakeMsgs + Sender + masterSecret + pad1));
	// sha_hash[20] = SHA(masterSecret + pad2 + 
	// 			      SHA(handshakeMsgs + Sender + masterSecret + pad1));
	// m = MD5(sslC->handshakeMsgs)
	//
	uchar out[36];
	sslP->paramP->handshakeMsgs[sslP->paramP->handshakeMsgsIndex] = '\0';
	sslP->paramP->clientHandshakeMsgs[sslP->paramP->clientHandshakeMsgsIndex] = '\0';
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, sslP->paramP->clientHandshakeMsgs, 
			strlen(sslP->paramP->clientHandshakeMsgs));
	printf("\n Length of Handshake Msgs sent by Client: %d", 
		sslP->paramP->clientHandshakeMsgsIndex);

	SHA_CTX sha1_ctx;
	SHA1_Init(&sha1_ctx);
	SHA1_Update(&sha1_ctx, sslP->paramP->clientHandshakeMsgs, 
			strlen(sslP->paramP->clientHandshakeMsgs));
	sslGenerateFinishedHash(&md5_ctx, &sha1_ctx, 
					sslP->paramP->masterSecret, out);
	memcpy(&p[9], &out[0], 36);
	
	length += 36;
	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	
	// Openssl data structure for encrypt/decrypt pointers
	// Called after sending CHANGE_CIPHER pkt to server
	// Function vectors set in ssl/s3_lib.c
	// ssl3_enc_method { 
	//   enc = ssl3_enc
	//   mac = n_ssl3_mac
	//   setup_key_block = ssl3_setup_key_block
	//   generate_master_secret = ssl3_generate_master_secret
	//   ...
	//   final_finish_mac = ssl3_final_finish_mac
	//   }
	//
	// Need to copy 2 functions from OpenSSL to generate all keys
	// ssl3_setup_key_block => ssl3_generate_key_block (ssl/s3_enc.c)
	// Need ssl3_enc()
	// Need to call ssl3_enc() just before sending the data out to the 
	// other side 
	printf("\n-> Send Client Finished");
	sendData(sslP, buff, length);
}

sendChangeCipherSpec(sslStruct *sslP, param_t *args) {
    uchar buff[1024];
    uchar *p = &buff[0];
    ushort length = 0;
    struct timeval tv;
    time_t curtime;
    int i;

    // Record Hdr (Type, Version, Length)
    p[0] = change_cipher_spec; //0x14
    p[1] = SSL_VERSION_1;
    p[2] = SSL_VERSION_2;
    PUT_BE16(&p[3], 1); // This pkt is only 1 byte in length
    length = RECORD_HDR_LEN;

    // Note that we have done 5 bytes by now, which should be substracted
    // from the pkt length for the RecordProtocol.
    p[5] = 1; // change ciper spec = 1
    length = length + 1;

    printf("\n-> Send Change Cipher Spec");
    sendData(sslP, buff, length);
}

sendServerKeyExchange (sslStruct *sslP, param_t *args) 	{ 
	// server_key_exchange = 12, client_key_exchange = 16
	args->hello_value = server_key_exchange; 
	sendClientKeyExchangeFinal(sslP, args);
}
sendClientKeyExchange (sslStruct *sslP, param_t *args) 	{ 
	// server_key_exchange = 12, client_key_exchange = 16
	args->hello_value = client_key_exchange; 
	sendClientKeyExchangeFinal(sslP, args);
    sendChangeCipherSpec(sslP, args);
	sleep(1);
    sendClientFinished(sslP, args);

}

sendClientKeyExchangeFinal (sslStruct *sslP, param_t *args) 	{ 
	uchar buff[1024];
	uchar plainText[256];
	uchar encryptedBuf[256];
	uchar *p = &buff[0];
	ushort length = 0;
	struct timeval tv;
	time_t curtime;
	int status, result;
	int i;

	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	// TLS ver 1.2 uses version value 3.3
	// SSL v3 is version 0300
	p[1] = SSL_VERSION_1;
	p[2] = SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = args->hello_value; // client_key_exchange = 16
	p[6] = 0;  // 3rd MSByte of the Length, usualy 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	/*
 	 *	If RSA is being used for key agreement and authentication, the
 	 *	client generates a 48-byte premaster secret, encrypts it using the
 	 *	public key from the server's certificate, and sends the result in
 	 *	an encrypted premaster secret message.  
 	 */
	// pre-master secret encrypted with Server's public key
	// Total Len = 48 bytes (2 byte version, 46 byte key)
	// Fil in the 2 Byte Version first
	plainText[0] = SSL_VERSION_1; 
	plainText[1] = SSL_VERSION_2;
	// Now fill in the secret key of 46 Bytes
	// Also save in sslP struct to create master secret
	strcpy(&plainText[2], "1234567890123456789012345678901234567890123456");
	memcpy(&(sslP->paramP->preMasterSecret[0]), &plainText[0], 48);
	result = encrypt(sslP, &plainText[0], &encryptedBuf[0], 48);
	log_info(fp, "\n Encrypted Len = %d", result);
	memcpy(&p[9], &encryptedBuf[0], result);
	length = length + result;

	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	// Save Client Msgs for making the Finished Msg
	memcpy(&(sslP->paramP->clientHandshakeMsgs[sslP->paramP->clientHandshakeMsgsIndex]), 
		&(p[5]), length-RECORD_HDR_LEN);
	sslP->paramP->clientHandshakeMsgsIndex = 
		sslP->paramP->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
	log_info(fp, "\n-> Send Client Key Exchange");
	sendData(sslP, buff, length);
}

// 2nd Phase of Testing - post ClientHello/ServerHello
int verifyAgainNull (sslStruct *sslP, param_t *args, int pkt, int verifyAlertCode) 	{ 
	return 0;
}
int sendAgainNull (sslStruct *sslP, param_t *args) 	{ 
	return 0;
}

int initSessionId (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	args->sessionID = 100;
}

int initServerHello (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	args->hello_value = server_hello; // 0x1
}

int initCipherCheck (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	// cypher suites
	args->cipher[0] = 0; 
	args->cipher[1] = 2; // Length of cypher suite
	args->cipher[2] = 0x99;
	args->cipher[3] = 0x99;
	args->cipherLen = 4;
}

int initParamsVerCheck (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	args->version_1 = 4;
	args->version_2 = 4;
}

int initParams (sslStruct *sslP, param_t *args) 	{ 
	struct timeval tv;
	time_t curtime;
	int i;

	sslP->paramP->handshakeResp = 0;
	sslP->paramP->verifyAlertCode = INVALID_CODE;
    sslP->paramP->handshakeMsgsIndex = 0; // Msgs recvd from Server for MD5/SHA1
    sslP->paramP->clientHandshakeMsgsIndex = 0; // Msgs saved for MD5/SHA1
    //memset(sslP->paramP->buff, 0, 1024);

	gettimeofday(&tv, NULL);
	curtime=tv.tv_sec;
	char buf[32];
	args->version_1 = SSL_VERSION_1;
	args->version_2 = SSL_VERSION_2;
	args->sessionID = 0;
	args->hello_value = client_hello; // 0x1
	
	// Random Structure
	PUT_BE32(&buf[0], curtime);
	for (i=4; i<=31; i++)
			buf[i] = 0;
	//Save the random value into sslP. Used later in the Finished msg
	memcpy(&(args->random[0]), &buf[0], 32);
	
	// cypher suites
	args->cipher[0] = 0; // Length of cypher suite
	args->cipher[1] = 2; // Length of cypher suite
	args->cipher[2] = TLS_RSA_WITH_RC4_128_SHA_1;
	args->cipher[3] = TLS_RSA_WITH_RC4_128_SHA_2;
	args->cipherLen = 4;
}

/*
 * Version used is 3.1 (TLS 1.0)
 * https://tools.ietf.org/html/rfc2246
 */
int sendHello (sslStruct *sslP, param_t *args) 	{ 
	uchar buff[1024];
	uchar *p = &buff[0];
	ushort length = 0;
	int i;

	log_debug(fp, "SSL: SendHello"); fflush(stdout);

	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	// SSL 3.0 is 0x0300, TLS ver 1.0 = 3.1, TLS 1.2 is 3.3, 
	// SSL_VERSION used here is 3.1
	p[1] = args->version_1; //SSL_VERSION_1;
	p[2] = args->version_2; //SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = args->hello_value; // client_hello = 0x1
	p[6] = 0;  // 3rd MSByte of the Length, usualy 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	p[9] =  args->version_1; // SSL_VERSION_1;
	p[10] =  args->version_2; // SSL_VERSION_2;
	length = length + 2;

	memcpy(&p[11], &(args->random[0]), 32); // copy from args into buffer
	length += 32;
	p[43] = args->sessionID; // sessionID
	length++;

	memcpy(&p[44], &(args->cipher[0]), args->cipherLen); 
	length += args->cipherLen; // currently set to 4

	p[48] = 1; //length of compression vector
	p[49] = 0; //compression algorithm
	length += 2;

	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	// Save Client Msgs for making the Finished Msg
	memcpy(&(args->clientHandshakeMsgs[args->clientHandshakeMsgsIndex]), 
	&(p[5]), length-RECORD_HDR_LEN);
	args->clientHandshakeMsgsIndex = 
		args->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
	log_debug(fp, "-> Send Client Hello, Len:%d", length); fflush(stdout);
	sendData(sslP, buff, length);
}

int verifyFailed2nd (sslStruct *sslP, param_t *args, int pkt, int verifyAlertCode) { 
	if (sslP->paramP->handshakeResp & (0x01 << pkt)) {
		log_debug(fp, "Pkt Recvd 2ndPhase - fail:%d, Recvd:%x", 
				pkt, sslP->paramP->handshakeResp); fflush(fp);
		sslTestsResults[args->testId].result = FAIL;
	} else {
		log_debug(fp, "Pkt NOT Recvd 2ndPhase - pass:%s, Recvd:%x", 
				msgToString(pkt), sslP->paramP->handshakeResp); fflush(fp);
		logRecvdPkts(sslP);  // For logging only
		sslTestsResults[args->testId].result = PASS;
	}
}

int verifyFailed (sslStruct *sslP, param_t *args, int pkt, int verifyAlertCode) { 
	if (sslP->paramP->handshakeResp & (0x01 << pkt)) {
		log_debug(fp, "Pkt Recvd.:%d, Recvd:%x", 
				pkt, sslP->paramP->handshakeResp); fflush(fp);
		sslTestsResults[args->testId].result = FAIL;
	} else {
		log_debug(fp, "Pkt NOT Recvd.:%s, Recvd:%x", 
				msgToString(pkt), sslP->paramP->handshakeResp); fflush(fp);
		logRecvdPkts(sslP);  // For logging only
		// We now check if there was an ALERT expected. and if it 
		// matches the recevied ALERT msg in the listen thread.
		if ((verifyAlertCode != INVALID_CODE) && 
		    (sslP->paramP->verifyAlertCode != INVALID_CODE)) {
			if (verifyAlertCode == sslP->paramP->verifyAlertCode) {
				log_info(fp, "\nSSL: ALERT Code matches for test:%d",
					args->testId); fflush(stdout);
				sslTestsResults[args->testId].result = PASS;
			} else {	
				log_info(fp, "\nSSL ERROR: ALERT Code mismatch for test:%d",
					args->testId); fflush(stdout);
				sslTestsResults[args->testId].result = FAIL;
			}
		} else {
			log_info(fp, "\nSSL: No ALERT recvd. for test:%d",
				args->testId); fflush(stdout);
			sslTestsResults[args->testId].result = PASS;
		}
	}
}
int verifyPassed (sslStruct *sslP, param_t *args, int pkt, int verifyAlertCode) { 
	if (sslP->paramP->handshakeResp & (0x01 << pkt)) {
		log_debug(fp, "Pkt Recvd.%d", pkt); fflush(fp);
		sslTestsResults[args->testId].result = PASS;
	} else {
		log_debug(fp, "Pkt NOT Recvd. %d", pkt); fflush(fp);
		sslTestsResults[args->testId].result = FAIL;
	}
}

/*
 * TBD: Generally, we should check for a receipt of ALERT, that indicates 
 * an SSL Protocol error and closure of SSL connection.
 * This function updates STATS file only.
 */
int updateStats (sslStruct *sslP, param_t *args, char* details) { 
	if (sslTestsResults[args->testId].result == PASS) {
		log_info(sslP->fsslStats, "Test ID: %s, Pass", 
			sslTestsResults[args->testId].cveId);
	} else {
		log_info(sslP->fsslStats, "Test ID: %s, Fail: Details:", 
			sslTestsResults[args->testId].cveId);
	}
	log_info(sslP->fsslStats, "Test Details: %s", details);
	fflush(sslP->fsslStats);
	return sslTestsResults[args->testId].result;
}

sslTestsDump() {
	char result[20];
	int i;

	for (i=0;i<SSL_NUM_TESTS;i++) {
		log_debug(fp, "--------------Test Results--------------");
		if (sslTestsResults[i].result == 1) strcpy(result, "pass"); 
		else strcpy(result, "fail");
		log_debug(fp, "Test ID: %s, Pass/Fail:%s", 
					sslTestsResults[i].cveId, result );
	}
	log_debug(fp, "----------------------------------------");
	fflush(fp);
}

static void signal_handler(int sig) {
	int i;
	if (sig == SIGUSR1) {
		log_info(fp, "\n SIGUSR1 !"); fflush(stdout);
		sslTestsDump();
	}
}

#include "sslTestCases"

signalRecvThread(sslStruct *sslP) {
	struct timespec tim1;
	tim1.tv_sec=0;
	tim1.tv_nsec=800000000L;
	if (nanosleep(&tim1, NULL) < 0) {
		log_error(sslP->fp, "SSL: Error: nanosleep call failed!");
		return -1;
	} 
	return 0;
}

sslTestsExec(sslStruct *sslP, jsonData_t* jsonData) {
	int i, status;
	struct sigaction sigact;
	struct timespec tim1;
	pthread_t recvThread;
	char result[20];

    initConnectionToServer(sslP, jsonData);
    status = pthread_create(&recvThread, NULL, &recvFunction, (void*)sslP);
    if (status != 0) { perror("Start Thread Error:"); return -1; }

	fp = sslP->fp; // ssl_logs
	// Initialize signals
    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGUSR1, &sigact, (struct sigaction*) NULL);

	for (i=0;i<SSL_NUM_TESTS;i++) {
		log_debug(sslP->fp, "Exec Test:%d", i); fflush(sslP->fp);
		sslP->paramP->testId = i;
		strncpy(sslTestsResults[i].cveId, sslTests[i].cveId, 
				strlen(sslTests[i].cveId));
		// The following call sets relevant sslP->paramP params
		sslTests[i].init_params(sslP, sslP->paramP);
		pthread_mutex_lock(&sslP->lock);
		sslTests[i].send(sslP, sslP->paramP);
		pthread_mutex_unlock(&sslP->lock);

		// Wait for recvThread to signal that we can proceed with 
		// the verification step below
		// TBD: For now, Sleep for 0.8 Sec, giving a chance to recvThread
		signalRecvThread(sslP);

		sslTests[i].verify(sslP, sslP->paramP, sslTests[i].firstRecvdPkt, sslTests[i].verifyAlertCode);
		if (sslTests[i].update_stats(sslP, sslP->paramP, sslTests[i].details) 
					== FAIL) {
			log_error(sslP->fp, "\nSSL: TestsExec: Failed Test %d", i);
			// We do not continue to 2nd phase of test, i.e. another pkt 
			// exhcnage, due to this error.
		} else {
		// 1st State Passed...
			// 2nd State, after ClientHello/ServerHello
			sslTests[i].send_again(sslP, sslP->paramP);
			signalRecvThread(sslP);
			sslTests[i].verify_again(sslP, sslP->paramP, sslTests[i].secondRecvdPkt, sslTests[i].verifyAlertCode);
			sslTests[i].update_stats(sslP, sslP->paramP, sslTests[i].details); 
		}
/* 
 * Note that in the results(), if we find there is a failure, the 
 * socket might be closed. So, we need to ensure that there is a 
 * new socket created, before running further tests.
 * In fact, let's create a new conn, for every test
 * Lill the recvThread too at this point, since we spawn it again
 */

// Final Cleanup
		close(sslP->sock);
		status = pthread_cancel(recvThread);
		if (status != 0) {
			log_error(sslP->fp, "\nSSL: Failed to cancel thread");
			fflush(sslP->fp);
			perror("SSL: Failed to cancel thread");
			exit(1);
		}
		sslP->paramP->handshakeResp = 0;
		 sslP->paramP->verifyAlertCode = INVALID_CODE;
    	initConnectionToServer(sslP, jsonData);
 		status = pthread_create(&recvThread, NULL, &recvFunction, 
					(void*)sslP);
    	if (status != 0) { perror("Start Thread Error:"); return -1; }
	} // for all tests

	// Put in a summary report into stats
	for (i=0;i<SSL_NUM_TESTS;i++) {
		log_info(sslP->fsslStats, "---------Test Results Summary------------");
		if (sslTestsResults[i].result == 1) strcpy(result, "pass"); 
		else strcpy(result, "fail");
		log_info(sslP->fsslStats, "Test ID: %s, Pass/Fail:%s", 
					sslTestsResults[i].cveId, result );
	}
	log_info(sslP->fsslStats, "---------------------------------------------");
	fflush(sslP->fsslStats);
}

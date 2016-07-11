/*
 * OpenVPN Tool
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
#include "../common/util.h"
#include "openvpn.h"
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

FILE *fp;
FILE *fovStats;
ovStruct_t ovS;

/*
 * --tls-auth is read in do_init_crypto_tls_c1() in src/vpn/init.c
 * by calling get_tls_handshake_key()
 * init_key_ctx()
 */
openvpn_encrypt(ovStruct_t *ovP, uchar *ptr, int length, int hmac_index) {
	uchar tmpPtr[5000];
	int tmpLen, i;
	uchar *hash;

	// 5th line for outgoing from server
	//uchar key[] = "\x25\x21\x1f\x2f\x4e\x2a\x50\x0d\x13\x3f\x19\xe2\x4c\xd5\xf5\x06\xc0\xa7\xe6\xf0";
	// 13th line for incoming into server
	uchar key[] = "\xac\x3c\x20\xbb\xb7\x54\x8d\x9a\x8d\x9c\x9f\xdd\x76\xde\x22\x14\x25\xfc\xcc\x07";

	memcpy(tmpPtr, ptr, length);
	memcpy(&tmpPtr[28], &tmpPtr[0], 9);
	tmpLen = length-28;
	// Copy pkt id + timestamp to the start of the pkt
	memcpy(&tmpPtr[20], &ptr[29], 8);
	tmpLen += 8;
	log_info(fp, "openvpn_encrypt: HMAC at:%d in pkt of len:%d, newlen:%d",
			hmac_index, length, tmpLen);
	fflush(fp);
	// Note that both the following HMAC versions work. Either way can be used.
	// Both have been tested with the openvpn_as server.
	{
	hash = HMAC(EVP_sha1(), key, strlen(key), &tmpPtr[20], tmpLen, NULL, NULL);
	}
	/*
	{
	unsigned char hash[SHA_DIGEST_LENGTH];
	uchar *output = NULL;
    HMAC_CTX hmac;
    unsigned int in_hmac_len = 0;
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, key, 20, EVP_sha1(), NULL);
    HMAC_Update(&hmac,  &tmpPtr[20], tmpLen);
    HMAC_Final(&hmac, hash, &in_hmac_len);
    HMAC_CTX_cleanup(&hmac);
	}*/
	
	// hash now contains the 20-byte SHA-1 hash
	memcpy(&ptr[hmac_index], hash, SHA_DIGEST_LENGTH);
#if DEBUG
	printf("\n HMAC KEY: ");
	for (i=0;i<20;i++)
		printf("%2x ",key[i]);
	printf("\n HMAC ON DATA: ");
	for (i=0;i<tmpLen;i++)
		printf("%2x ",tmpPtr[20+i]);
	printf("\n HMAC SHA1: ");
	for (i=0;i<20;i++)
		printf("%2x ",hash[i]);
#endif
}

/*
 * Record Hdr   : T V L(2 bytes)
 * 		22 - Handshake
 * 		V: 0x301
 * 		L: 1430
 * Handshake Hdr: T L(3 bytes) CertLen (3 Bytes)
 * Handshake Hdr Len is 4 bytes smaller than Record Hdr Len
 * 		(to cater for T and L of Handshake Hdr)
 * Handshake Hdr:
 * 		11 - Certificate
 * 		Len - 1426
 * 		Cert Len - 1423 ( 3 less than Handshake Hdr len)
 * 		Cert Len - This is individual Cert Len (3 Bytes)
 * 			signedCert	algo identifier	padding	encrypted data
 * 		Cert Len - This is individual Cert Len (3 Bytes)
 * 			signedCert	algo identifier	padding	encrypted data
 * 		(These could be multiple Certs starting with  Len....)
 */
int addCert (ovStruct_t *ovP, char* p) {
	ulong opensslerr=0;
	int bufflen = 200;
	char buff[bufflen];

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	FILE *fCert = fopen("openvpn/asethi.pem", "r");
	if (fCert == NULL) {
		log_error(fp, "OPENVPN: error opening cert pem file");
		return -1;
	}
	// Load certificate
	X509 *cert = PEM_read_X509(fCert, NULL, NULL, NULL);
	opensslerr = ERR_get_error();
	if (opensslerr != 0) {
		log_error(fp, "OPENVPN: reading cert error");
		return -1;
	}
	fclose(fCert);
	log_info(fp, "OpenVPN: certificate read"); fflush(fp);
	X509_NAME *name = X509_get_subject_name(cert);
	char *nameStr = X509_NAME_oneline(name, buff, bufflen);
	log_info(fp, "Subject: %s", nameStr); fflush(fp);

	// Get Cert Len once converted into DER
	int certLen = i2d_X509(cert, NULL);
	opensslerr = ERR_get_error();
	if (opensslerr != 0) {
		log_error(fp, "OPENVPN: reading cert len error");
		return -1;
	}
	log_info(fp, "CertLen: %d", certLen); fflush(fp);
	uchar *certBuff = (uchar*)malloc(certLen);
	uchar *tmpPtr = certBuff;
	if (i2d_X509(cert, &certBuff) < 0) {
		opensslerr = ERR_get_error();
		ERR_error_string_n(opensslerr, buff, bufflen);
		log_error(fp, "OPENVPN: erro converting cert to buff: %s", buff);
		return -1;
	}
	memcpy(p, tmpPtr, certLen);
	return certLen;
}

int addClientCert (ovStruct_t *ovP, char* p) {
    ushort length = 0;
	uchar random[32];
    char cipher[3];
    int cipherLen;
    time_t curtime;
    int i, len;

    log_debug(fp, "OPENVPN SSL: Send Client Cert"); fflush(stdout);

    // Record Hdr (Type, Version, Length)
    p[0] = 0x16;
    // SSL 3.0 is 0x0300, TLS ver 1.0 = 3.1, TLS 1.2 is 3.3, 
    // SSL_VERSION used here is 3.1
    p[1] = SSL_VERSION_1;
    p[2] = SSL_VERSION_2;
    PUT_BE16(&p[3], 0); // **** fill in this later at this point
    // current length, used by sendData, and also in pkt
    length = RECORD_HDR_LEN;

    // Note that we have done 5 bytes by now, which should be substracted
    // from the pkt length for the RecordProtocol.

    p[5] = 11; // certificate
    length = length + 1;
    p[6] = 0;  // 3rd MSByte of the Length, usualy 0
    p[9] = 0;  // 3rd MSByte of the Length, usualy 0
    p[12] = 0;  // 3rd MSByte of the Length, usualy 0
    length = length + 9; // 2 cert lenths

    // Starting p[6,7,8], we have outer cert len
    // Starting p[9,10,11], we have inner cert len
    // Starting p[12,13,14], we have inner cert len
    printf("\nAdding certificate"); fflush(stdout);
	len = addCert(ovP, &p[15]);
	length += len; // Cert contents
    // length of Certificate pkt following length field = 1 byte
    PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
    PUT_BE16(&p[10], length-RECORD_HDR_LEN-7);
    PUT_BE16(&p[13], length-RECORD_HDR_LEN-10);
    // Finally fill in the length of Record headers
    PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	return length;
}

/*
 * Check for:
 *  - cert identity matching domain name
 *  - cert is within validity perios
 *  - digital sig is valid
 */
verifyOvCertificate(ovStruct_t *ovP) {
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
    buff = ovP->certBuff;
    len = ovP->certLen;
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
        ovP->rsa_key = public_key->pkey.rsa;
        // Both the following are printable strings and need to be freed 
        // by caling OPENSSL_free()
        rsa_e_dec = BN_bn2dec(ovP->rsa_key->e); // RSA Exponent
        rsa_n_hex = BN_bn2hex(ovP->rsa_key->n); // RSA Modulus
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

ovEncrypt (ovStruct_t *ovP, char *buff, char *encryptedBuf, int len) {
    int padding = RSA_PKCS1_PADDING;
    int result;

    // The encrypted bufer must be of size RSA_size(rsa_key)
    log_info(fp, "\nRSA Size = %d", RSA_size(ovP->rsa_key));
    result = RSA_public_encrypt(len, buff, encryptedBuf,
                ovP->rsa_key, padding);
    return result;
}

int addSslClientKeyExchange (ovStruct_t *ovP, char* p) {
    uchar buff[1024];
    uchar plainText[256];
    uchar encryptedBuf[256];
    ushort length = 0;
    struct timeval tv;
    time_t curtime;
    int status, result, i;

    log_debug(fp, "OPENVPN SSL: SendClientKeyExchange"); fflush(stdout);

    // Record Hdr (Type, Version, Length)
    p[0] = 0x16;
    // SSL 3.0 is 0x0300, TLS ver 1.0 = 3.1, TLS 1.2 is 3.3, 
    // SSL_VERSION used here is 3.1
    p[1] = SSL_VERSION_1;
    p[2] = SSL_VERSION_2;
    PUT_BE16(&p[3], 0); // **** fill in this later at this point
    // current length, used by sendData, and also in pkt
    length = RECORD_HDR_LEN;

    // Note that we have done 5 bytes by now, which should be substracted
    // from the pkt length for the RecordProtocol.

    p[5] = client_key_exchange;
    p[6] = 0;  // 3rd MSByte of the Length, usualy 0
    // length of Handshake pkt following length field = 1 byte
    PUT_BE16(&p[7], 0); // **** fill in this later at this point
    length = length + 4;

    /*
     *  If RSA is being used for key agreement and authentication, the
     *  client generates a 48-byte premaster secret, encrypts it using the
     *  public key from the server's certificate, and sends the result in
     *  an encrypted premaster secret message.  
     */
    // pre-master secret encrypted with Server's public key
    // Total Len = 48 bytes (2 byte version, 46 byte key)
    // Fil in the 2 Byte Version first
    plainText[0] = SSL_VERSION_1;
    plainText[1] = SSL_VERSION_2;
    // Now fill in the secret key of 46 Bytes
    // Also save in ovP struct to create master secret
    strcpy(&plainText[2], "1234567890123456789012345678901234567890123456");
    memcpy(&(ovP->preMasterSecret[0]), &plainText[0], 48);
    result = ovEncrypt(ovP, &plainText[0], &encryptedBuf[0], 48);
    log_info(fp, "\n Encrypted Len = %d", result);
    memcpy(&p[9], &encryptedBuf[0], result);
    length = length + result;

    // Finally fill in the lengths of Record and Handshake headers
    PUT_BE16(&p[3], length-RECORD_HDR_LEN);
    PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
    // Save Client Msgs for making the Finished Msg
    memcpy(&(ovP->clientHandshakeMsgs[ovP->clientHandshakeMsgsIndex]),
        &(p[5]), length-RECORD_HDR_LEN);
    ovP->clientHandshakeMsgsIndex =
        ovP->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
    log_info(fp, "\n-> Send Client Key Exchange");
	return length;
}

// RFC SSL 3.0 https://tools.ietf.org/html/rfc6101
/*
 * Version used is 3.1 (TLS 1.0)
 * https://tools.ietf.org/html/rfc2246
 */
int addSslHello (ovStruct_t *ovP, char* p) {
    ushort length = 0;
	uchar random[32];
    char cipher[3];
    int cipherLen;
    time_t curtime;
    int i;

    log_debug(fp, "OPENVPN SSL: SendHello"); fflush(stdout);

    // Record Hdr (Type, Version, Length)
    p[0] = 0x16;
    // SSL 3.0 is 0x0300, TLS ver 1.0 = 3.1, TLS 1.2 is 3.3, 
    // SSL_VERSION used here is 3.1
    p[1] = SSL_VERSION_1;
    p[2] = SSL_VERSION_2;
    PUT_BE16(&p[3], 0); // **** fill in this later at this point
    // current length, used by sendData, and also in pkt
    length = RECORD_HDR_LEN;

    // Note that we have done 5 bytes by now, which should be substracted
    // from the pkt length for the RecordProtocol.

    p[5] = 0x01; // client_hello = 0x1
    p[6] = 0;  // 3rd MSByte of the Length, usualy 0
    // length of Handshake pkt following length field = 1 byte
    PUT_BE16(&p[7], 0); // **** fill in this later at this point
    length = length + 4;

    p[9] =  SSL_VERSION_1;
    p[10] = SSL_VERSION_2;
    length = length + 2;

	// Random Struct
    PUT_BE32(&random[0], curtime);
    for (i=4; i<=31; i++)
            random[i] = 0;
    memcpy(&p[11], &(random[0]), 32); 
    length += 32;
    p[43] = 0; // sessionID
    length++;

    // cypher suites
    cipher[0] = 0; // Length of cypher suite
    cipher[1] = 2; // Length of cypher suite
    cipher[2] = TLS_RSA_WITH_RC4_128_SHA_1;
    cipher[3] = TLS_RSA_WITH_RC4_128_SHA_2;
    cipherLen = 4;
    memcpy(&p[44], &(cipher[0]), cipherLen);
    length += cipherLen; // currently set to 4

    p[48] = 1; //length of compression vector
    p[49] = 0; //compression algorithm
    length += 2;

    // Finally fill in the lengths of Record and Handshake headers
    PUT_BE16(&p[3], length-RECORD_HDR_LEN);
    PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
    // Save Client Msgs for making the Finished Msg
    memcpy(&(ovP->clientHandshakeMsgs[ovP->clientHandshakeMsgsIndex]),
    &(p[5]), length-RECORD_HDR_LEN);
    ovP->clientHandshakeMsgsIndex =
        ovP->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
    log_debug(fp, "-> Send Client Hello, Len:%d", length); fflush(stdout);
	return length;
}


void ovListener (ovStruct_t *ovP) {
	int sock;
    uchar buff[5000];  // uchar is important
    int bytes_recv, index, i, j;
    int set = 0;
    int remBytes = 0;
    ushort RecordHdrLengthRecvd = 0;
	jsonData_t* jsonData = ovP->jsonData;
	int ssl_len;
	int saveLen = 0;
	uchar saveBuff[5000];

	log_info(fp, "Entering OpenVPN Listener Loop..."); fflush(fp);
	while(1) {
        bytes_recv = recv(ovP->sock,&buff[0], 3000, 0);
        log_debug(fp, "OpenVPN Bytes_recv = %d, ", bytes_recv); fflush(fp);
        if (bytes_recv == -1) { perror("-1: Error during recv: "); exit(1); }
        if (bytes_recv == 0) {
            log_error(fp, "OpenVPN: Error: recvFunction: sock closed in recv, bytes_Recv = 0"); fflush(fp);
            sleep(10); // This is so that the main has time to gather stats
            exit(1); // No point keeping this since the sock is gone
        }
        switch((buff[0] & P_KEYID_MASK) >> 3) {
        case P_CONTROL_HARD_RESET_SERVER_V2:
            log_info(fp, "  <- OV: P_CONTROL_HARD_RESET_SERVER_V2"); 
			fflush(fp);
			ovP->toAck = GET_BE32(&buff[50]);
			memcpy(ovP->toSessionID, &buff[1], 8);
			log_info(fp, "toAck = %d", ovP->toAck); fflush(fp);
			log_info(fp, "\nOpenVPN toSession ID: ");
			for (j=0;j<8;j++)
				printf("%2x ", ovP->toSessionID[j]);
			fflush(stdout);
			sendAckV1(ovP, jsonData);
			sleep(1);
			sendClientHello(ovP, jsonData);
			break;
        case P_ACK_V1:
            log_info(fp, "  <- OV: P_ACK_V1"); 
			fflush(fp);
			break;
        case P_CONTROL_V1:
            log_info(fp, "  <- OV: P_CONTROL_V1"); fflush(fp);
			// Note that if saveLen is non Zero, then we have a continued 
			// SSL packet and we need to keep collecting the SSL pkt till
			// we get the complete pkt.
			if (saveLen != 0) {
				// Continuing pkts do not have ACK data, and thus their
				// len is 42 bytes.
				ovP->toAck = GET_BE32(&buff[38]);
				log_info(fp, "toAck: %d", ovP->toAck); fflush(fp);
				memcpy(&saveBuff[saveLen], &buff[42], bytes_recv-42);
				saveLen = saveLen + bytes_recv - 42;
				saveBuff[3] = saveBuff[3] & 0x7F; // clears the MSB flag
				ssl_len=GET_BE16(&saveBuff[3]);
				if (saveLen >= (ssl_len+5)) {
					log_info(fp, "We have complete SSL pkt %d of %d",
						saveLen, ssl_len+5); fflush(fp);
					// Control falls down to decoding the SSL hdr
					memcpy(buff, saveBuff, (ssl_len+5));
					index=0;
					// But, first set the next ssl pkt if partially recvd.
					memcpy(saveBuff, &saveBuff[ssl_len+5], saveLen-(ssl_len+5));
					saveLen = saveLen - (ssl_len+5);
					log_info(fp, "We have next partial SSL pkt of size %d",
						saveLen); fflush(fp);
				} else {
					log_info(fp, "We have partial SSL pkt %d of %d",
						saveLen, ssl_len+5); fflush(fp);
					sendAckV1(ovP, jsonData);
					continue;
				}	
			} else {
				ovP->toAck = GET_BE32(&buff[50]);
				// This occurs 1st time only for a complete or a partial pkt
				index = 54;
				buff[index+3] = buff[index+3] & 0x7F; // clears the MSB flag
				ssl_len = GET_BE16(&buff[index+3]);
				// If there is more than ssl_len+54+5 then we need to look for the 
				// 2nd SSL pkt now.
				if (bytes_recv > ssl_len+54+5) {
					int left =  bytes_recv - (ssl_len+54+5);
					log_info(fp, "Left over bytes: %d", left);
					fflush(fp);
					memcpy(&saveBuff[saveLen], &buff[ssl_len+54+5], left);
					saveLen += left;
				}
			}
			// Check in the pkt now to see the SSL Pkt type
			// Assuming 54 bytes OpenVPN Hdr, it the peer also is acking
			// the Client Hello pkt, we need to jump these many bytes to 
			// start decoding the SSL header.
        	switch(buff[index]) {
	        case change_cipher_spec:
   	             log_info(fp, "  <- SSL: Change Cipher: %d", ssl_len+5); break;
   	     	case alert:
   	             log_info(fp, "  <- SSL: Alert: %d", ssl_len+5); break;
   	     	case handshake:
   	             log_info(fp, "  <- SSL: Handshake: %d", ssl_len+5); break;
   	     	case application_data:
   	             log_info(fp, "  <- SSL: App data: %d", ssl_len+5); break;
   	     	default:
   	             log_error(fp, " <- SSL: Error pkt recvd: %d, ", buff[0]);
			}
        	if (buff[index] == change_cipher_spec) { break; }
        	if (buff[index] == alert) { break; }
			// TBD: Logic needed to read multiple Handshake msgs in 1 msg
			switch(buff[index+5]) {
        	case hello_request:
                log_info(fp, "      <- Handshake Type: Hello Request"); break;
        	case client_hello:
                log_info(fp, "      <- Handshake Type: Client Hello"); break;
        	case server_hello:
                log_info(fp, "      <- Handshake Type:  Server Hello");
                //recvServerHello(ovP);
                break;
        	case certificate:
                log_info(fp, "      <- Handshake Type: Certificate");
                //recvCertificate (ovP);
                break;
        	case server_key_exchange:
                log_info(fp, "      <- Handshake Type: Server Key Exchange");
                //ovP->handshakeResp |= set;
                break;
        	case certificate_request:
                log_info(fp, "      <- Handshake Type: Certificate Request");
				// TBD: Check if Server Hello Done is also in this message
				// We need a smarter way to parse multiple handshake msgs
				// so that we dont use this kludge here
				if (buff[bytes_recv-4] == 0x0E) {
                	log_info(fp, "      <- Handshake Type: Server Hello Done");
					ovSendClientCertificate(ovP, jsonData);
					ovSendClientKeyExchange(ovP, jsonData);
				}
                break;
        	case server_hello_done:
                log_info(fp, "      <- Handshake Type:  Server Hello Done");
                //recvServerHelloDone(ovP);
                break;
        	case certificate_verify:
                log_info(fp, "      <- Handshake Type: Certificate Verify"); break;
                break;
        	case client_key_exchange:
                log_info(fp, "      <- Handshake Type: Client Key Exchange"); break;
                break;
        	case finished:
                log_info(fp, "      <- Handshake Type: Finished");
                break;
        	default:
                log_info(fp, "      <- Handshake Type: Unknown");
			}
			sendAckV1(ovP, jsonData);
			break;
        default:
            log_error(fp, " <- OV: Error pkt recvd: %d, ", buff[0]);
            // We have some junk data. Throw it away
            log_info(fp, "..discarding %d len data\n", bytes_recv); continue;
        }
#ifdef DEBUG
		for (j=0;j<i;j++)
			printf("%2x ", buff[j]);
		fflush(fp);
#endif
	}
	exit(0);
}

ovUDPSend(ovStruct_t *ovP, uchar *ptr, int length) {
	int sent, i;
	//log_info(fp, "ovUDPSend: %d to sock:%d", length, ovP->sock);
	fflush(fp);
	sent = sendto(ovP->sock, ptr, length, 0, 
		(struct sockaddr *)&ovP->server_addr, sizeof(ovP->server_addr));
	if(sent < 0) {
		perror("sendto failed"); return 0;
	}
    log_info(fp, "ovUDPSend sent %d Bytes", sent); fflush(fp);
}

int initConnectionToServerOV(ovStruct_t *ovP, jsonData_t* jsonData) {
    struct sockaddr_in server_addr;
	int sock;

    if((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("socket:");
            log_error(fp, "OPENVPN ERROR: create creation socket"); fflush(fp);
            exit(1);
    }
    ovP->server_addr.sin_family = AF_INET;
    ovP->server_addr.sin_port = htons(1194);
    if(inet_aton(jsonData->serverIP, &ovP->server_addr.sin_addr) == 0) {
            log_error(fp, "inet_aton() failed\n");
            log_error(fp, "OPENVPNSSL ERROR: create in inet_aton"); fflush(fp);
    }
    log_info(fp, "OPENVPN: UDP Connected to %s:%d at sock:%d",
		jsonData->serverIP, 1194, sock);
	fflush(fp);
	return sock;
}

ovSendClientCertificate (ovStruct_t *ovP, jsonData_t *jsonData) {
	char buff[1024];
    struct timeval tv;
    time_t curtime;
	int i, index, hmac_index, len;
	int tlsAuth = 1;
	
    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
	// Pkt type - 1 byte P_CONTROL_HARD_RESET_CLIENT_V2
	buff[0] = P_CONTROL_V1 << 3;
	// session id - 8 bytes
    PUT_BE32(&buff[1], 0);
    PUT_BE32(&buff[5], 1);
	index = 9;
	// Put the Overall seq number for replay protection and timestamp
	// only if tlsAuth is enabled for this client.
	if (tlsAuth == 1) {
		// HMAC - 20 bytes
		hmac_index=index;
		for (i=0;i<20;i++)
			buff[index+i] = 0x0;
		index += 20;
		// Replay Packet ID = 1
    	PUT_BE32(&buff[index], ovP->replayNo);
		ovP->replayNo++;
		index += 4;
		// Time Stamp - not needed in case of TLS - but, we put this 
		// for initial pkts
    	PUT_BE32(&buff[index], curtime);
		index += 4;
	}
	// ACK + ACK Buffer = 0;
	buff[index] = 0x0; index+=1;
	/* Note that we do not put any 4 byte seq id, if the ACK shows 0 bytes 
	for (i=0;i<4;i++)
		buff[index+i] = 0x0;
	index+=4;
	 */
	PUT_BE32(&buff[index], ovP->seqNo); ovP->seqNo++;
	index +=4;
	len = addClientCert(ovP, &buff[index]);
	index += len;
	openvpn_encrypt(ovP, buff, index, hmac_index);
	ovUDPSend(ovP, buff, index);
}

ovSendClientKeyExchange (ovStruct_t *ovP, jsonData_t *jsonData) {
	char buff[1024];
    struct timeval tv;
    time_t curtime;
	int i, index, hmac_index, len;
	int tlsAuth = 1;
	
    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
	// Pkt type - 1 byte P_CONTROL_HARD_RESET_CLIENT_V2
	buff[0] = P_CONTROL_V1 << 3;
	// session id - 8 bytes
    PUT_BE32(&buff[1], 0);
    PUT_BE32(&buff[5], 1);
	index = 9;
	// Put the Overall seq number for replay protection and timestamp
	// only if tlsAuth is enabled for this client.
	if (tlsAuth == 1) {
		// HMAC - 20 bytes
		hmac_index=index;
		for (i=0;i<20;i++)
			buff[index+i] = 0x0;
		index += 20;
		// Replay Packet ID = 1
    	PUT_BE32(&buff[index], ovP->replayNo);
		ovP->replayNo++;
		index += 4;
		// Time Stamp - not needed in case of TLS - but, we put this 
		// for initial pkts
    	PUT_BE32(&buff[index], curtime);
		index += 4;
	}
	// ACK + ACK Buffer = 0;
	buff[index] = 0x0; index+=1;
	/* Note that we do not put any 4 byte seq id, if the ACK shows 0 bytes 
	for (i=0;i<4;i++)
		buff[index+i] = 0x0;
	index+=4;
	 */
	PUT_BE32(&buff[index], ovP->seqNo); ovP->seqNo++;
	index +=4;
	len = addSslClientKeyExchange(ovP, &buff[index]);
	index += len;
	openvpn_encrypt(ovP, buff, index, hmac_index);
	ovUDPSend(ovP, buff, index);
}


sendClientHello (ovStruct_t *ovP, jsonData_t *jsonData) {
	char buff[1024];
    struct timeval tv;
    time_t curtime;
	int i, index, hmac_index, len;
	int tlsAuth = 1;
	
    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
	// Pkt type - 1 byte P_CONTROL_HARD_RESET_CLIENT_V2
	buff[0] = P_CONTROL_V1 << 3;
	// session id - 8 bytes
    PUT_BE32(&buff[1], 0);
    PUT_BE32(&buff[5], 1);
	index = 9;
	// Put the Overall seq number for replay protection and timestamp
	// only if tlsAuth is enabled for this client.
	if (tlsAuth == 1) {
		// HMAC - 20 bytes
		hmac_index=index;
		for (i=0;i<20;i++)
			buff[index+i] = 0x0;
		index += 20;
		// Replay Packet ID = 1
    	PUT_BE32(&buff[index], ovP->replayNo);
		ovP->replayNo++;
		index += 4;
		// Time Stamp - not needed in case of TLS - but, we put this 
		// for initial pkts
    	PUT_BE32(&buff[index], curtime);
		index += 4;
	}
	// ACK + ACK Buffer = 0;
	buff[index] = 0x0; index+=1;
	/* Note that we do not put any 4 byte seq id, if the ACK shows 0 bytes 
	for (i=0;i<4;i++)
		buff[index+i] = 0x0;
	index+=4;
	 */
	PUT_BE32(&buff[index], ovP->seqNo); ovP->seqNo++;
	index +=4;
	len = addSslHello(ovP, &buff[index]);
	index += len;
	openvpn_encrypt(ovP, buff, index, hmac_index);
	ovUDPSend(ovP, buff, index);
}


sendAckV1(ovStruct_t *ovP, jsonData_t *jsonData) {
	char buff[1024];
    struct timeval tv;
    time_t curtime;
	int i, index, hmac_index;
	int tlsAuth = 1;
	
    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
	// Pkt type - 1 byte P_ACK_V1
	buff[0] = P_ACK_V1 << 3;
	// session id - 8 bytes
    PUT_BE32(&buff[1], 0);
    PUT_BE32(&buff[5], 1);
	index = 9;
	// Put the Overall seq number for replay protection and timestamp
	// only if tlsAuth is enabled for this client.
	if (tlsAuth == 1) {
		// HMAC - 20 bytes
		hmac_index=index;
		for (i=0;i<20;i++)
			buff[index+i] = 0x0;
		index += 20;
		// Replay Packet ID
    	PUT_BE32(&buff[index], ovP->replayNo);
		ovP->replayNo++;
		index += 4;
		// Time Stamp - not needed in case of TLS - but, we put this 
		// for initial pkts
    	PUT_BE32(&buff[index], curtime);
		index += 4;
	}
	// ACK + ACK Buffer = 0;
	buff[index] = 0x1; index+=1;
	PUT_BE32(&buff[index], ovP->toAck); 
	index+=4;
	memcpy(&buff[index], ovP->toSessionID, 8);
	index +=8;
	openvpn_encrypt(ovP, buff, index, hmac_index);
	ovUDPSend(ovP, buff, index);
}


sendHardReset(ovStruct_t *ovP, jsonData_t *jsonData) {
	char buff[1024];
    struct timeval tv;
    time_t curtime;
	int i, index, hmac_index;
	int tlsAuth = 1;
	
    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
	// Pkt type - 1 byte P_CONTROL_HARD_RESET_CLIENT_V2
	buff[0] = 0x38;
	// session id - 8 bytes
    PUT_BE32(&buff[1], 0);
    PUT_BE32(&buff[5], 1);
	index = 9;
	// Put the Overall seq number for replay protection and timestamp
	// only if tlsAuth is enabled for this client.
	if (tlsAuth == 1) {
		// HMAC - 20 bytes
		hmac_index=index;
		for (i=0;i<20;i++)
			buff[index+i] = 0x0;
		index += 20;
		// Replay Packet ID = 1
    	PUT_BE32(&buff[index], ovP->replayNo);
		ovP->replayNo++;
		index += 4;
		// Time Stamp - not needed in case of TLS - but, we put this 
		// for initial pkts
    	PUT_BE32(&buff[index], curtime);
		index += 4;
	}
	// ACK + ACK Buffer = 0;
	buff[index] = 0x0; index+=1;
	/* Note that we do not put any 4 byte seq id, if the ACK shows 0 bytes 
	for (i=0;i<4;i++)
		buff[index+i] = 0x0;
	index+=4;
	 */
	PUT_BE32(&buff[index], ovP->seqNo); ovP->seqNo++;
	index +=4;
	openvpn_encrypt(ovP, buff, index, hmac_index);
	ovUDPSend(ovP, buff, index);
}

void ovExec(jsonData_t* jsonData) {
	ovStruct_t *ovP = &ovS;
	ovP->seqNo = 0;
	ovP->replayNo = 1;
    ovP->clientHandshakeMsgsIndex = 0;


	ovP->sock = initConnectionToServerOV(ovP, jsonData); 
	sendHardReset(ovP, jsonData);
}

void* ovStart(void *args) {
	pthread_t threadPID;
	char filePath[100];

	jsonData_t* jsonData = (jsonData_t*)args;

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ov_stats");
	fovStats = fopen(filePath, "a");
	log_info(fovStats, "OpenVPN started: custID: %d, server:%s", 
			jsonData->custID, jsonData->serverIP);

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ov_logs");
	fp = fopen(filePath, "a");
	log_info(fp, "OpenVPN started: custID: %d, server:%s", 
			jsonData->custID, jsonData->serverIP);
	log_info(fp, "OpenVPN config: ovProto: %s", jsonData->ovProto);
	fflush(fp);

	ovExec(jsonData);

	if (pthread_create(&threadPID, NULL, ovListener, &ovS)) {
		log_info(fp, "\nError creating OpenVPN Listener Thread"); fflush(stdout);
		exit(1);
	}
	fflush(fp);

	// TBD: For now use this to ensure that the listener runs and is 
	// waiting for pkts
	while(1) {
		sleep(2); 
		continue;
	}

	fclose(fp);
	fclose(fovStats);
	return 0;
}


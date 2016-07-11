/* For Parsing Certificates */
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
/* end */

#define SSL_VERSION_1 3
#define SSL_VERSION_2 1
#define RECORD_HDR_LEN 5
#define SSL_INNER_HDR_LEN 4
typedef enum {
        change_cipher_spec = 20, alert = 21, handshake = 22,
        application_data = 23
} ContentType;

/* Record Protocol Header **********/
typedef enum {  
          hello_request=0, client_hello=1, server_hello=2,
          certificate=11, server_key_exchange =12,
          certificate_request=13, server_hello_done=14,
          certificate_verify=15, client_key_exchange=16,
          finished=20
} HandshakeType;

// TBD - change the following as _1 and _2 
#define TLS_RSA_WITH_NULL_MD5 "0x00,0x01"
#define TLS_RSA_WITH_NULL_SHA "0x00,0x02"
#define TLS_RSA_WITH_NULL_SHA256 "0x00,0x3B"
#define TLS_RSA_WITH_RC4_128_MD5 "0x00,0x04"
#define TLS_RSA_WITH_RC4_128_SHA_1 0x00
#define TLS_RSA_WITH_RC4_128_SHA_2 0x05
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA "0x00,0x0A"
#define TLS_RSA_WITH_AES_128_CBC_SHA  "0x00,0x2F"
#define TLS_RSA_WITH_AES_256_CBC_SHA  "0x00,0x35"
#define TLS_RSA_WITH_AES_128_CBC_SHA256 "0x00,0x3C"
#define TLS_RSA_WITH_AES_256_CBC_SHA256 "0x00,0x3D"

/* packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte */
#define P_KEY_ID_MASK              0x07
#define P_OPCODE_SHIFT             3
#define P_KEYID_MASK               0xF8 

/* packet opcodes -- the V1 is intended to allow protocol changes in the future */
#define P_CONTROL_HARD_RESET_CLIENT_V1 1     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V1 2     /* initial key from server, forget previous state */
#define P_CONTROL_SOFT_RESET_V1        3     /* new key, graceful transition from old to new key */
#define P_CONTROL_V1                   4     /* control channel packet (usually TLS ciphertext) */
#define P_ACK_V1                       5     /* acknowledgement for packets received */
#define P_DATA_V1                      6     /* data channel packet */
#define P_DATA_V2                      9     /* data channel packet with peer-id */

/* indicates key_method >= 2 */
#define P_CONTROL_HARD_RESET_CLIENT_V2 7     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V2 8     /* initial key from server, forget previous state */


typedef struct {
    FILE *fp;
    FILE *fovStats;
    char selfIP[INET_ADDRSTRLEN];
	jsonData_t* jsonData;

    // Unit under test
    struct sockaddr_in server_addr;
    int sock;
    int seqNo;
    int replayNo;

	// For SSL
    uchar clientHandshakeMsgs[6000];
    int clientHandshakeMsgsIndex;
    uchar preMasterSecret[48];
    RSA *rsa_key;
    uchar *certBuff; // cert recvd in Server Hello
    int certLen;

	// Recvd from the peer
    int toAck;
	uchar toSessionID[8];
} ovStruct_t;


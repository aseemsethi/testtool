#include <linux/if_packet.h> //sll
#include <sys/ioctl.h> // SIOCGIFADDR
#include <net/if.h>
#include "../common/util.h"
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
#include <openssl/ssl.h>

#define INTERFACE "eth0"
#define SSL_PORT 4433
// RFC SSL 3.0 https://tools.ietf.org/html/rfc6101
#define SSL_VERSION_1 3
#define SSL_VERSION_2 0
#define RECORD_HDR_LEN 5
#define SSL_INNER_HDR_LEN 4

// Events
#define HELLO_REQ               0
#define CLIENT_HELLO    1
#define SERVER_HELLO    2
#define CERTIFICATE             3
#define SERVER_KEY_EXCHANGE     4
#define CERTIFICATE_REQ         5
#define SERVER_HELLO_DONE       6
#define CERTIFICATE_VERIFY      7
#define CLIENT_KEY_EXCHANGE     8
#define FINISHED                        9
#define CHANGE_CIPHER_SPEC      10
// States
#define SSL_INIT 0
#define SSL_HELLO_DONE_RECVD 1
#define SSL_CHANGE_CIPHER_SPEC_RECVD 2
#define SSL_FINISHED_RECVD 3

#define INVALID_CODE 1000

typedef struct {
    // Set before every test
    int testId;

    // Values that the program modifies
    int version_1;
    int version_2;
	int sessionID;
	char cipher[3];
	int cipherLen;
	int hello_value;

    int state;
    uchar *buff;  // used as recv buffer only
    int buffLen;
    char srcIP[20];
    ushort srcPort;
    //char sessionIDLen;
    //char sessionID[40];
    int versionResp[2];
    int handshakeResp;
	int verifyAlertCode;
    RSA *rsa_key;
    // Stuff needed to create MasterSecret
    uchar handshakeMsgs[6000];
    int handshakeMsgsIndex;
    uchar clientHandshakeMsgs[6000];
    int clientHandshakeMsgsIndex;
    uchar random[32];
    uchar serverRandom[32];
    uchar preMasterSecret[48];
    uchar masterSecret[48];
} param_t;

typedef struct {
	FILE *fp;
	FILE *fsslStats;
    char selfIP[INET_ADDRSTRLEN];

    // Unit under test
    struct sockaddr_in server_addr;
    struct sockaddr_ll sll;
    int sock;
    param_t *paramP;
	pthread_mutex_t lock;

	// For SSL Perf
    int id;
    SSL_CTX *ctx;
    SSL *ssl;
} sslStruct;

/**********
 Record Protocol Header
 **********/
typedef enum {
        change_cipher_spec = 20, alert = 21, handshake = 22,
        application_data = 23
} ContentType;

typedef struct {
          uchar major;
          uchar minor;
} ProtocolVersion;

typedef struct {
        ContentType type;
        ProtocolVersion version;
        u16 length;
} RecordHdrPlainTxt;
/**********
 Record Protocol Header
 **********/
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

#define SSL3_AD_CLOSE_NOTIFY                   0 
#define SSL3_AD_UNEXPECTED_MESSAGE            10  
#define SSL3_AD_BAD_RECORD_MAC                20     
#define TLS1_AD_DECRYPTION_FAILED             21    
#define TLS1_AD_RECORD_OVERFLOW               22   
#define SSL3_AD_DECOMPRESSION_FAILURE         30  
#define SSL3_AD_HANDSHAKE_FAILURE             40 
#define SSL3_AD_NO_CERTIFICATE                41
#define SSL3_AD_BAD_CERTIFICATE               42      
#define SSL3_AD_UNSUPPORTED_CERTIFICATE       43     
#define SSL3_AD_CERTIFICATE_REVOKED           44    
#define SSL3_AD_CERTIFICATE_EXPIRED           45   
#define SSL3_AD_CERTIFICATE_UNKNOWN           46  
#define SSL3_AD_ILLEGAL_PARAMETER             47 
#define TLS1_AD_UNKNOWN_CA                    48
#define TLS1_AD_ACCESS_DENIED                 49      
#define TLS1_AD_DECODE_ERROR                  50     
#define TLS1_AD_DECRYPT_ERROR                 51    
#define TLS1_AD_EXPORT_RESTRICTION            60   
#define TLS1_AD_PROTOCOL_VERSION              70  
#define TLS1_AD_INSUFFICIENT_SECURITY         71 
#define TLS1_AD_INTERNAL_ERROR                80
#define TLS1_AD_USER_CANCELLED                90   
#define TLS1_AD_NO_RENEGOTIATION             100  


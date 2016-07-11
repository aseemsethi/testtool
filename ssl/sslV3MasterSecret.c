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
//#include "../xmlparser/xmlparse.h"
#include "../common/util.h"
#include "ssl.h"

int ssl3_generate_master_secret(sslStruct *sslC,
		unsigned char *out, unsigned char *p, int len)
	{
	static const unsigned char *salt[3]={
#ifndef CHARSET_EBCDIC
		(const unsigned char *)"A",
		(const unsigned char *)"BB",
		(const unsigned char *)"CCC",
#else
		(const unsigned char *)"\x41",
		(const unsigned char *)"\x42\x42",
		(const unsigned char *)"\x43\x43\x43",
#endif
		};
	unsigned char buf[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;
	int i,ret=0;
	unsigned int n;
	const EVP_MD *md5;
	const EVP_MD *sha1;
#define SSL3_RANDOM_SIZE 32
	md5  = EVP_md5();
	sha1 = EVP_sha1();
	EVP_MD_CTX_init(&ctx);
	for (i=0; i<3; i++)
		{
		EVP_DigestInit_ex(&ctx,sha1, NULL);
		EVP_DigestUpdate(&ctx,salt[i],strlen((const char *)salt[i]));
		EVP_DigestUpdate(&ctx,p,len);
		EVP_DigestUpdate(&ctx,&(sslC->paramP->random[0]),
			SSL3_RANDOM_SIZE);
		EVP_DigestUpdate(&ctx,&(sslC->paramP->serverRandom[0]),
			SSL3_RANDOM_SIZE);
		EVP_DigestFinal_ex(&ctx,buf,&n);

		EVP_DigestInit_ex(&ctx,md5, NULL);
		EVP_DigestUpdate(&ctx,p,len);
		EVP_DigestUpdate(&ctx,buf,n);
		EVP_DigestFinal_ex(&ctx,out,&n);
		out+=n;
		ret+=n;
		}
	EVP_MD_CTX_cleanup(&ctx);
	return(ret);
}

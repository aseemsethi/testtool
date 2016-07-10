#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "pthread.h"
#include "errno.h"
#include <sys/stat.h>
#include "parser.h"
#include "log.h"

FILE *flog;
pthread_t sslPID, sslPerfPID, httpPID, ovPID;

jsonData_t* parse (char*, FILE *flog, char* configFile);
void* sslStart(void *args);
void* sslPerfStart(void *args);
void* httpStart(void *args);
void* bgpStart(void *args);
void* ovStart(void *args);

startOpenVpnThread(jsonData_t* jsonData) {
	struct stat st;
	char filePath[100];
	
	// Create OPENVPN thread
	log_debug(flog, "CUST: Create OPENVPN thread.."); fflush(flog);
/*
	if (pthread_create(&ovPID, NULL, ovStart, (void*)jsonData)) {
		log_error(flog, "Error creating OPENVPN Thread"); fflush(flog);
		exit(1);
	}
*/
	fflush(flog);
}

startBgpThread (jsonData_t* jsonData) {
	struct stat st;
	char filePath[100];
	
	// Create BGP thread
	log_debug(flog, "CUST: Create BGP thread.."); fflush(flog);
	if (pthread_create(&httpPID, NULL, bgpStart, (void*)jsonData)) {
		log_error(flog, "Error creating BGP Thread"); fflush(flog);
		exit(1);
	}
	fflush(flog);
}

startHttpThread (jsonData_t* jsonData) {
	struct stat st;
	char filePath[100];
	
	// Create HTTP thread
	log_debug(flog, "CUST: Create HTTP thread.."); fflush(flog);
/*
	if (pthread_create(&httpPID, NULL, httpStart, (void*)jsonData)) {
		log_error(flog, "Error creating HTTP Thread"); fflush(flog);
		exit(1);
	}
*/
	fflush(flog);
}

startSslPerfThread (jsonData_t* jsonData) {
	struct stat st;
	char filePath[100];
	
	// Create SSL thread
	log_debug(flog, "CUST: Create SSL thread.."); fflush(flog);
/*
	if (pthread_create(&sslPerfPID, NULL, sslPerfStart, (void*)jsonData)) {
		log_error(flog, "Error creating SSL Perf Thread"); fflush(flog);
		exit(1);
	}
*/
	fflush(flog);
}

startSslThread (jsonData_t* jsonData) {
	struct stat st;
	char filePath[100];
	
	// Create SSL thread
	log_debug(flog, "CUST: Create SSL thread.."); fflush(flog);
/*
	if (pthread_create(&sslPID, NULL, sslStart, (void*)jsonData)) {
		log_error(flog, "Error creating SSL Thread"); fflush(flog);
		exit(1);
	}
*/
	fflush(flog);
}

/*
 * This is called with "prog", "name", "id". The "name" is the monitor 
 * process that needs to be started. 
 * Open the log file and read the config file
 * Start the Monitor thread that has been requested.
 *
 *    ./tool 100 bgp [config-file]
 */
main(int argc, char *argv[]) {
	jsonData_t* jsonData;
	char filePath[200], configFile[200];

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], argv[1]);
	sprintf(&filePath[strlen(filePath)], "/logs");
	printf("\n %s", filePath);
	flog = fopen(filePath, "a");
	if (flog == NULL) {
		printf("\nDir missing /var/monT/%s: Exiting mont_cust process",
				argv[1]);
		fflush(stdout); return;
	}

	if (argc == 4) {
		log_debug(flog, "Tool Start with Config File: %d params:%s:%s:%s", argc, argv[1], argv[2], argv[3]);
		jsonData = parse(argv[1], flog, argv[3]);
	} else {
		log_debug(flog, "Tool Start: %d params:%s:%s", argc, argv[1], argv[2]);
		// Read in the config for customer id: argv[1]
		jsonData = parse(argv[1], flog, NULL);
	}
	if (jsonData == NULL) {
		log_error(flog, "Config error in /var/monT/%s: Exiting mont_cust process", argv[1]);
		fflush(flog); goto error;
	}
	if(strcasecmp(argv[2], "ssl") == 0) {
		log_info(flog, "SSL Functional Testing..");
		startSslThread(jsonData);
	} else if(strcasecmp(argv[2], "ssl_perf") == 0) {
		log_info(flog, "SSL Performance Testing..");
		startSslPerfThread(jsonData);
	} else if(strcasecmp(argv[2], "http") == 0) {
		log_info(flog, "HTTP Testing..");
		startHttpThread(jsonData);
	} else if(strcasecmp(argv[2], "bgp") == 0) {
		log_info(flog, "BGP Testing..");
		startBgpThread(jsonData);
	} else if(strcasecmp(argv[2], "openvpn") == 0) {
		log_info(flog, "OpenVPN Testing..");
		startOpenVpnThread(jsonData);
	}
	fflush(flog);
error:
	// TBD : Start CLI parser thread here, vs sleeping
	cliLoop();
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "../jsmn/jsmn.h"
#include "parser.h"

int mainParser(void);

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
            strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

/*
 * configFile takes presendence. If this is NULL, then id is used
 * to pick up the file at /var/monT/100/config.json
 */
jsonData_t* parse (char* id, FILE *flog, char* configFile) {
	jsmn_parser p;
	jsmntok_t *tok;
	size_t tokcount = 256;
	int i, r, len, tlen, ret;
#define BUFFSIZE 8048
	char buff[BUFFSIZE];
	FILE *fp;
	char filePath[100];
	jsonData_t* jsonData;
	jsmntok_t *t;
	int nIndex = 0;
	int pathIndex = 0;
	int wIndex = 0;

	// jsonData is returnd to the caller, that needs to free it
	jsonData = malloc(sizeof(jsonData_t));
	if (jsonData == NULL) {
		log_debug(flog, "\n Malloc failure while alocation jsonData");
		return NULL;
	}
	jsonData->url[0] = '\0';

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], id);
	sprintf(&filePath[strlen("/var/monT/")+strlen(id)], "/config.json");

	// ConfigFile gets preference
	if (configFile != NULL)
		strcpy(filePath, configFile);

	log_debug(flog, "Opening Customer Config File: %s", filePath);
	fp = fopen(filePath, "r");
	if (fp == NULL) {
		log_error(flog, "Config file not present..");
		fflush(flog);
		return NULL;
	}

	len = (int)fread(buff, sizeof(char), BUFFSIZE, fp); 
	log_debug(flog,"Read %d bytes from config file", len);

	jsmn_init(&p);
	tok = malloc(sizeof(*tok) * tokcount);
	if (tok == NULL) {
		log_error(flog, "malloc error in parser");
		exit(1);
	}
    r = jsmn_parse(&p, buff, len, tok, tokcount);
    if (r < 0) {
            if (r == JSMN_ERROR_NOMEM) {
				log_error(flog, "Parse: Allocate more mem to tok"); return NULL; }
			if (ret == JSMN_ERROR_INVAL) {
				log_error(flog, "Parse: invalid JSON string"); return NULL; }
			if (ret == JSMN_ERROR_PART) {
				log_error(flog, "Parse: truncated JSON string"); return NULL; }
	} else {
		char s[20];
		log_debug(flog, "jsmn returned %d tokens", r);
		for (i = 0; i < r; i++) {
			strncpy(s, buff + tok[i+1].start,  tok[i+1].end-tok[i+1].start); 
			s[tok[i+1].end-tok[i+1].start] = '\0';
			log_debug(flog, "%.*s: %.*s", 
					tok[i].end-tok[i].start, buff + tok[i].start,
					tok[i+1].end-tok[i+1].start, buff + tok[i+1].start);
			if (jsoneq(buff, &tok[i], "Params") == 0) {
				log_debug(flog, "  ****"); i++; continue;
			} 
			if (jsoneq(buff, &tok[i], "custID") == 0) {
				jsonData->custID = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "serverIP") == 0) {
				strcpy(jsonData->serverIP, s); 
			} else if (jsoneq(buff, &tok[i], "sslPort") == 0) {
				jsonData->sslPort = strtol(s, NULL,0); 
			} else if (jsoneq(buff, &tok[i], "sslPerSec") == 0) {
				jsonData->sslPerSec = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "totalConn") == 0) {
				jsonData->totalConn = strtol(s, NULL,0); 
			} else if (jsoneq(buff, &tok[i], "helloPerSec") == 0) {
				jsonData->helloPerSec = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "totalHello") == 0) {
				jsonData->totalHello = strtol(s, NULL,0); 
			} else if (jsoneq(buff, &tok[i], "url") == 0) {
				strncpy(jsonData->url, buff + tok[i+1].start,  tok[i+1].end-tok[i+1].start); jsonData->url[tok[i+1].end-tok[i+1].start] = '\0';
			} else if (jsoneq(buff, &tok[i], "httpVerbose") == 0) {
				jsonData->httpVerbose = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "httpParallel") == 0) {
				jsonData->httpParallel = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "pktSize") == 0) {
				jsonData->pktSize = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "httpRepeat") == 0) {
				jsonData->httpRepeat = strtol(s, NULL,0);
// OpenVPN Params
			} else if (jsoneq(buff, &tok[i], "ovProto") == 0) {
				strcpy(jsonData->ovProto, s); 
// BGP Stuff
			} else if (jsoneq(buff, &tok[i], "routerID") == 0) {
				strcpy(jsonData->routerID, s); 
			} else if (jsoneq(buff, &tok[i], "version") == 0) {
				jsonData->version = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "myas") == 0) {
				jsonData->myas = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "withdrawn len") == 0) {
				jsonData->withdrawnLen = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "withdrawn prefix") == 0) {
				jsonData->withdrawnPrefix[wIndex] = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "withdrawn route") == 0) {
				strcpy(&jsonData->withdrawnRoute[wIndex][0], s); 
				wIndex++;
// BGP Stuff - path attributes
			} else if (jsoneq(buff, &tok[i], "path attribute len") == 0) {
				jsonData->pathAttrLen = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "path flag") == 0) {
				jsonData->pathFlag[pathIndex] = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "path type") == 0) {
				jsonData->pathType[pathIndex] = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "path value") == 0) {
				jsonData->pathValue[pathIndex] = strtol(s, NULL,0);
				pathIndex++;
			} else if (jsoneq(buff, &tok[i], "path value nexthop") == 0) {
				strcpy(&jsonData->pathValueNextHop[pathIndex][0], s); 
				pathIndex++;
			} else if (jsoneq(buff, &tok[i], "path len") == 0) {
				jsonData->pathLen[pathIndex] = strtol(s, NULL,0);
// BGP Stuff - NRI
			} else if (jsoneq(buff, &tok[i], "nlri len") == 0) {
				jsonData->nlriLen[nIndex] = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "nlri prefix") == 0) {
				strcpy(&jsonData->nlriPrefix[nIndex][0], s); 
				nIndex++;
			} else if (jsoneq(buff, &tok[i], "repeat nlri") == 0) {
				jsonData->nlriRepeat = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "repeat delay") == 0) {
				jsonData->nlriRepeatDelay = strtol(s, NULL,0);
			} else if (jsoneq(buff, &tok[i], "repeat update") == 0) {
				jsonData->repeatUpdate = strtol(s, NULL,0);
			}
			i++; 
		}
	}
	fflush(flog);
	fclose(fp);
	jsonData->nIndex =  nIndex;
	jsonData->pathIndex =  pathIndex;
	jsonData->wIndex =  wIndex;
	return jsonData;
}

main() {
	FILE *fc;
	jsonData_t* jsonData;

	fc = fopen("/var/monT/100/config.json", "a");
	jsonData = parse("100", stdout, NULL);
	mainParser();
}

/*
 * Code taken and modified from https://curl.haxx.se/libcurl/c/10-at-a-time.html
 */
#include <stdio.h>
#include <string.h>
#include "../common/parser.h"
/* somewhat unix-specific */ 
#include <sys/time.h>
#include <unistd.h>
/* curl stuff */ 
#include <curl/curl.h>
#include "../common/log.h"

static const char *urls[] = {
  "http://www.opensource.org",
  "http://www.google.com",
  "http://www.yahoo.com",
  "http://www.ibm.com",
  "http://www.aryaka.com",
  "http://www.sophos.com",
  "http://www.cisco.com",
  "http://www.amazon.com",
  "http://www.ebay.com",
  "http://www.sapnaonline.com",
};
#define CNT sizeof(urls)/sizeof(char*)  
#define MAX_PARALLEL 100
int verbose;

/*
 * Called for data recvd, via CURLOPT_WRITEFUNCTION
 */
static size_t cb(char *d, size_t n, size_t l, void *p)
{
  /* take care of the data here, ignored in this example */ 
  (void)d;
  (void)p;
  return n*l;
}

CURL* init(CURLM *cm, int i, char* url) {
  CURL *eh = curl_easy_init();

  if (i >= CNT) i = 1;  // since we have only these many URLs, 
						// assign the last one to all remaining handles
 
  // The following disables output to stdout
  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, cb);

  curl_easy_setopt(eh, CURLOPT_HEADER, 0L);
  if (url == NULL) {
    curl_easy_setopt(eh, CURLOPT_URL, urls[i]);
    curl_easy_setopt(eh, CURLOPT_PRIVATE, urls[i]);
  } else {
    curl_easy_setopt(eh, CURLOPT_URL, url);
    curl_easy_setopt(eh, CURLOPT_PRIVATE, url);
  }
  curl_easy_setopt(eh, CURLOPT_VERBOSE, verbose);
    /* Ask for filetime */
  curl_easy_setopt(eh, CURLOPT_FILETIME, 1L);

  curl_multi_add_handle(cm, eh);
	return eh;
}

int curl_main(jsonData_t *jsonData, FILE *fhttpStats, FILE *fp)
{
  CURL *handles[MAX_PARALLEL];
  CURLM *multi_handle;
  int C;
  int still_running; /* keep number of running handles */ 
  int i;
  CURLMsg *msg; /* for picking up messages with the transfer status */ 
  int msgs_left; /* how many messages are left */ 
  int httpParallel = jsonData->httpParallel;
  verbose = jsonData->httpVerbose;
  int completed = 0;

  /* init a multi stack */ 
  multi_handle = curl_multi_init();
 
again: 
  /* Allocate one CURL handle per transfer */ 
  if (strlen(jsonData->url) == 0) {
    log_info(fp, "\n No url given, auto assign urls");
    for(i=0; i<httpParallel; i++)
		handles[i] = init(multi_handle, i, NULL);
  } else {
    log_info(fp, "\n url given -  assign it to all handles");
    for(i=0; i<httpParallel; i++)
		handles[i] = init(multi_handle, i, jsonData->url);
  }
  /* we start some action by calling perform right away */ 
  log_info(fhttpStats, "Starting multi handle: %d parallel sessions, Repeat Index: %d", httpParallel, completed);
  fflush(fhttpStats);
  curl_multi_perform(multi_handle, &still_running);
 
  do {
    struct timeval timeout;
    int rc; /* select() return code */ 
    CURLMcode mc; /* curl_multi_fdset() return code */ 
 
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;
 
    long curl_timeo = -1;
 
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);
 
    /* set a suitable timeout to play around with */ 
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
 
    curl_multi_timeout(multi_handle, &curl_timeo);
    if(curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if(timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
        timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }
 
    /* get file descriptors from the transfers */ 
    mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
 
    if(mc != CURLM_OK) {
      log_error(fp, "curl_multi_fdset() failed, code %d.\n", mc); fflush(fp);
      break;
    }
 
    /* On success the value of maxfd is guaranteed to be >= -1. We call
       select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
       no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
       to sleep 100ms, which is the minimum suggested value in the
       curl_multi_fdset() doc. */ 
 
    if(maxfd == -1) {
      struct timeval wait = { 0, 100 * 1000 }; /* 100ms */ 
      rc = select(0, NULL, NULL, NULL, &wait);
    } else {
      /* Note that on some platforms 'timeout' may be modified by select().
         If you need access to the original value save a copy beforehand. */ 
      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
    }
 
    switch(rc) {
    case -1:
      /* select error */ 
      break;
    case 0: /* timeout */ 
    default: /* action */ 
      curl_multi_perform(multi_handle, &still_running);
      break;
    }
  } while(still_running);
 
  /* See how the transfers went */ 
  while((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
    if(msg->msg == CURLMSG_DONE) {
		char *url;
		long respcode, redirect;
		double dlSpeed, filesize;
		time_t filetime;
        CURL *e = msg->easy_handle;
        curl_easy_getinfo(e, CURLINFO_PRIVATE, &url);
		curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &respcode);
		curl_easy_getinfo(e, CURLINFO_REDIRECT_COUNT, &redirect);
		curl_easy_getinfo (e, CURLINFO_SPEED_DOWNLOAD, &dlSpeed);
        curl_easy_getinfo(e, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);
        curl_easy_getinfo(e, CURLINFO_FILETIME, &filetime);
        log_info(fp, "R: %d - %s <%s>",
                msg->data.result, curl_easy_strerror(msg->data.result), url); 
		fflush(fp);
        log_info(fhttpStats, "R: %d - %s <%s>",
                msg->data.result, curl_easy_strerror(msg->data.result), url);
        log_info(fhttpStats, "Stats: respcode:%d, redirect-count:%d, dlSpeed:%.2fKB/sec, filesize:%0.0f, filetime:%s", 
			respcode, redirect, dlSpeed/1024, filesize, ctime(&filetime)); 
		fflush(fhttpStats);
      } else {
        log_error(fp, "E: CURLMsg (%d)\n", msg->msg); fflush(fp);
      }	
  }

  completed += 1;
  if (completed < jsonData->httpRepeat) {
	printf("\n HTTP Repeating.....");
    goto again;
  }
 
  curl_multi_cleanup(multi_handle);
 
  /* Free the CURL handles */ 
  for(i=0; i<httpParallel; i++) {
    curl_multi_remove_handle(multi_handle, handles[i]);
    curl_easy_cleanup(handles[i]);
  }
 
  return 0;
}

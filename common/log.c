#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include "log.h"

void log_format (FILE *fp, const char* tag, const char* message, va_list args) {
	time_t now;
	time(&now);
	char * date =ctime(&now);   
	date[strlen(date) - 1] = '\0';  
	fprintf(fp, "\n%s [%s] ", date, tag);  
	vfprintf(fp, message, args);
/*
	if (strcmp(tag, "Alert") == 0) {
		openlog("Monitor", LOG_CONS|LOG_PID|LOG_NDELAY|LOG_PERROR, LOG_LOCAL0);
		syslog(LOG_ERR, message, args);
		closelog();
	}
*/
}

/*
 * TBD: log_alert to be updated to log to syslog daemon
 */
void log_stats(FILE *fp, const char* message, ...) {  
	va_list args;   
	va_start(args, message);    
	log_format(fp, "STATS", message, args);     
	va_end(args); 
}

// Log Alert is a syslog msg too
void log_alert(FILE *fp, const char* message, ...) {  
	va_list args;   

	va_start(args, message);    
	log_format(fp, "Alert", message, args);     
	va_end(args); 

/* Send to syslog */
	va_start(args, message);    
	openlog("Monitor", LOG_CONS|LOG_PID|LOG_NDELAY|LOG_PERROR, LOG_LOCAL0);
	syslog(LOG_ERR, message, args);
	closelog();
	va_end(args); 
}
void log_error(FILE *fp, const char* message, ...) {  
	va_list args;   
	va_start(args, message);    
	log_format(fp, "error", message, args);     
	va_end(args); 
}
void log_info(FILE *fp, const char* message, ...) {   
	va_list args;   
	va_start(args, message);    
	log_format(fp, "info", message, args);  va_end(args); 
}
void log_debug(FILE *fp, const char* message, ...) {  
	va_list args;   
	va_start(args, message);    
	log_format(fp, "debug", message, args);     
	va_end(args); 
}

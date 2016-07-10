#ifndef LOG_H
#define LOG_H

void log_alert(FILE *fp, const char* message, ...); 
void log_error(FILE *fp, const char* message, ...); 
void log_info(FILE *fp, const char* message, ...); 
void log_debug(FILE *fp, const char* message, ...);

#endif /* LOG_H */

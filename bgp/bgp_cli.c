#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h> // SIOCGIFADDR
#include <netinet/in.h>
#include "../common/log.h"
#include "bgp.h"

extern bgp_t bgp;

CLIsendUpdate(char *fileName) {
    FILE *fu;
    char filePath[100];

    sprintf(filePath, fileName);
    fu = fopen(filePath, "r");
    if (fu == NULL) {
        printf("Update file %s not present..", filePath); fflush(stdout);
        return -1;
    }
    sendUpdateFile(&bgp, fu);
}

CLIsendWithdraw(char *fileName) {
    FILE *fw;
    char filePath[100];

    sprintf(filePath, fileName);
    fw = fopen(filePath, "r");
    if (fw == NULL) {
        printf("Withdraw file %s not present..", filePath); fflush(stdout);
        return -1;
    }
    sendUpdateWithdrawFile(&bgp, fw);
}


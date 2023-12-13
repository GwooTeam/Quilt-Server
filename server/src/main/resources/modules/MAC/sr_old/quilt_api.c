#include <stdio.h>

void printVal(const char* title, unsigned char* ptr, size_t valLen) {

    int i;
    fprintf(stdout, "%s", title);
    for(i=0; i<valLen; i++) 
        fprintf(stdout, "%02x", ptr[i]);

}


void hexToByte(const char *hexStr, unsigned char* bytes, size_t byteLen) {

    size_t i;
    for (i = 0; i < byteLen; ++i) 
        sscanf(&hexStr[i * 2], "%02x", &bytes[i]);

}

#include "crypt_freesec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "triperino.h"

#define TESTERINO2

#ifdef TESTERINO
char pw1[] = "tripcode";
char pw2[] = "XgoL/N;u";
char pw3[] = "t:ipcode";
char pw4[9];
char salt1[3];
char salt2[3];
char salt3[3];
int seed = 101;
#endif

#ifdef TESTERINO2
char pat[TRUNCATE_LEN] = "swag";
#endif

int main()
{
    printf("Hello World\n");
    _crypt_extended_init(); 
    #ifdef TESTERINO
    struct php_crypt_extended_data buffer; 
    memset(&buffer, 0, sizeof(buffer));
    salterino(pw1, salt1);
    salterino(pw2, salt2);
    salterino(pw3, salt3);
    char *hash1 = _crypt_extended_r(pw1, salt1, &buffer);
    shifterino(hash1);
    printf(hash1);
    printf("\n");
    memset(&buffer, 0, sizeof(buffer));
    char *hash2 = _crypt_extended_r(pw2, salt2, &buffer);
    shifterino(hash2);
    printf(hash2);
    printf("\n");
    memset(&buffer, 0, sizeof(buffer));
    char *hash3 = _crypt_extended_r(pw3, salt3, &buffer);
    shifterino(hash3);
    printf(hash2);
    printf("\n");
    generate_pw(&seed, pw4);
    printf(pw4);
    printf("\n");
    #endif

    #ifdef TESTERINO2
    search(pat, 0); 
    #endif 
    return 0; 
}


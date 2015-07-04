#include "triperino.h"
#include "crypt_freesec.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

void shifterino(char *hash)
{
    int i;
    int start = strlen(hash) - TRUNCATE_LEN;
    for (i = 0; i <= TRUNCATE_LEN; i++)
    {
        hash[i] = hash[start + i];
    }
}

void salterino(char *pw, char *salt)
{
    salt[0] = pw[1];
    salt[1] = pw[2];
    salt[2] = '\0';
    if (salt[0] < VALID_MIN || salt[0] > VALID_MAX)
        salt[0] = '.';
    if (salt[1] < VALID_MIN || salt[1] > VALID_MAX)
        salt[0] = '.';

    if (salt[0] >= REPLACE_MIN && salt[0] <= REPLACE_MAX)
        salt[0] += REPLACE_OFFSET;
    else if (salt[0] >= REPLACE_MIN_2 && salt[0] <= REPLACE_MAX_2)
        salt[0] += REPLACE_OFFSET_2; 

    if (salt[1] >= REPLACE_MIN && salt[1] <= REPLACE_MAX)
        salt[1] += REPLACE_OFFSET;
    else if (salt[1] >= REPLACE_MIN_2 && salt[1] <= REPLACE_MAX_2)
        salt[1] += REPLACE_OFFSET_2; 
    /*
    if (!isalnum(salt[0]))
    {
        int valid_len = strlen(valid);
        int i;
        int valid_0 = 0;
        int valid_1 = 0; 
        for(i = 0; i < valid_len; i++)
        {
            if (salt[0] == valid[i])
                valid_0 = 1;
            if (salt[1] == valid[i])
                valid_1 = 1;
        }
        if (!valid_0)
            salt[0] = '.';
        if (!valid_1)
            salt[1] = '.';
    }
    */
}

void generate_pw(int *seed, char *pw)
{
    int i = 0;
    int end = 0;
    int cur;
    for (i = 0; i < MAX_PW_LEN; i++)
    {
        cur = rand_r(seed) % (VALID_LEN + 2) - 1; 
        if (cur >= 0)
        {
            pw[end] = cur + VALID_MIN;
            end++;
        }
    }
    pw[end] = '\0';
}

void generate_pw_fast(uint32_t *x, uint32_t *y, uint32_t *z, uint32_t *w,\
char *pw)
{
    int i = 0;
    int end = 0;
    int cur; 
    uint32_t t;
    for (i = 0; i < MAX_PW_LEN; i++)
    {
        t = *x ^ (*x << 11);
        *x = *y; *y = *z; *z = *w;
        *w = *w ^ (*w >> 19) ^ t ^ (t >> 8);
        
        cur = *w  % (VALID_LEN + 2) - 1; 
        if (cur >= 0)
        {
            pw[end] = cur + VALID_MIN;
            end++;
        }
    }
    pw[end] = '\0';

}

void search(const char pat[TRUNCATE_LEN], const int case_sens)
{
    char lower_pat[TRUNCATE_LEN];
    char lower_hash[TRUNCATE_LEN];
    char pw[MAX_PW_LEN];
    char salt[SALT_LEN];
    int i;
    int seed = 100;
    for (i = 0; pat[i]; i++)
    {
        lower_pat[i] = tolower(pat[i]);
    }
    lower_pat[i] = '\0';

    int j = 0;
    
    struct php_crypt_extended_data buffer; 
    memset(&buffer, 0, sizeof(buffer));
    
    int x, y, z, w;
    x = 1;
    y = 2;
    z = 3;
    w = 4;

    while (j < 10000000)
    {
        generate_pw_fast(&x, &y, &z, &w, pw);
        salterino(pw, salt);  
        char *hash = _crypt_extended_r(pw, salt, &buffer);
        shifterino(hash);
        if (strstr(hash, pat))
        {
            printf("FOUND: %s : %s\n", pw, hash);
        } 
        else if(!case_sens)
        {
            for(i = 0; hash[i]; i++)
            {
                lower_hash[i] = tolower(hash[i]);
            }     
            lower_hash[i] = '\0';
            if (strstr(lower_hash, lower_pat))
            {
                printf("FOUND: %s : %s\n", pw, hash);
            } 

        }
        j++;
    } 
}


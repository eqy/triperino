#ifndef TRIPERINO_H
#define TRIPERINO_H

#define SALT_LEN 2
#define TRUNCATE_LEN 10

#define VALID_MIN 46
#define VALID_MAX 122
#define VALID_LEN VALID_MAX - VALID_MIN

#define REPLACE_MIN 58
#define REPLACE_MAX 64
#define REPLACE_OFFSET 7

#define REPLACE_MIN_2 91
#define REPLACE_MAX_2 96
#define REPLACE_OFFSET_2 6

#define MAX_PW_LEN 8
/* static char valid[] = "./:;<=>?@[\\]^_`"; */



void shifterino(char *hash);

void salterino(char *pw, char *salt);

void generate_pw(int *seed, char *pw);

void search(const char pat[9], const int case_sens);

#endif

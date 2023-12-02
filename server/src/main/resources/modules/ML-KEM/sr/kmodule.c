#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "nsc_api.h"
#include "kyber_keygen.h"
#include "kyber_encapsulate.h"
#include "kyber_decapsulate.h"
#include "kyber_encrypt.h"
#include "kyber_decrypt.h"

#include "kyber_keygen_raw.h"
#include "kyber_encapsulate_raw.h"
#include "kyber_decapsulate_raw.h"
#include "kyber_encrypt_raw.h"
#include "kyber_decrypt_raw.h"

// 프로그램 전달 인수로 뭘 넣을지는 아직 정의되지 않음.
int main(int argc, char* argv[]) {

    int option; // switch 대상 변수

    // flags
    unsigned int flag_keygen = 0;
    unsigned int flag_encap = 0;
    unsigned int flag_decap = 0;
    unsigned int flag_encrypt = 0;
    unsigned int flag_decrypt = 0;

    unsigned int flag_file = 0;
    unsigned int flag_raw = 0;

    // args. must be NULL.
    char* key = NULL;
    char* target = NULL;
    char* result = NULL;
    char* type = NULL;

    // strcut option의 배열 long_options[]
    // 여기는 긴 옵션 (--)들 설정
    // struct option { 옵션이름, 값 여부, 처리결과 플래그 포인터, 옵션 식별 정수(문자) }
    struct option long_options[] = {
        {"keygen", no_argument, &flag_keygen, 'a'}, // 비대칭 키 생성
        {"encap", no_argument, &flag_encap, 'b'}, // 키 캡슐화
        {"decap", no_argument, &flag_decap, 'c'}, // 키 디캡슐화
        {"encrypt", no_argument, &flag_encrypt, 'd'}, // 데이터 암호화
        {"decrypt", no_argument, &flag_decrypt, 'e'}, // 데이터 복호화

        {"key", required_argument, 0, '1'}, // 사용할 키
        {"target", required_argument, 0, '2'}, // 대상 파일 경로
        {"result", optional_argument, 0, '3'}, // 결과 저장 경로
        {0, 0, 0, 0}
    };
    

    // 짧은 옵션(-)은 그냥 여기서 switch case로 넣으면 됨. ab: 문자열이랑 같이.
    while ((option = getopt_long(argc, argv, "fr", long_options, NULL)) != -1) {
        switch (option) {
        // key
        case '1':
            key = optarg;
            break;

        // target
        case '2':
            target = optarg;
            break;

        // result
        case '3':
            result = optarg;
            break;

        case '4':
            type = optarg;
            break;
        
        case 'f':
            flag_file = 1;
            break;
        
        case 'r':
            flag_raw = 1;
            break;

        // 옵션 못 알아먹었을 때
        case '?':
            printf("into case ?\n");
            if(optopt == 'b') {
                fprintf(stderr, "옵션 -%c는 값이 필요합니다.\n", optopt);
            }
            else if (isprint(optopt)) {
                fprintf(stderr, "알 수 없는 옵션: %c\n", optopt);
            }
            else {
                fprintf(stderr, "알 수 없는 문자: \\x%x\n", optopt);
            }
            goto err;
            break;

        default:
            // printf("into default case\n");
            break;
        }
    }

    // puts("check flags");
    // printf("flag_keygen: %d\n", flag_keygen);
    // printf("flag_encap: %d\n", flag_encap);
    // printf("flag_decap: %d\n", flag_decap);
    // printf("flag_encrypt: %d\n", flag_encrypt);
    // printf("flag_decrypt: %d\n", flag_decrypt);

    // puts("check paths");
    // printf("keypath: %s\n", key);
    // printf("target: %s\n", target);
    // printf("result: %s\n", result);

    if(flag_raw) {
        if(flag_keygen) {
            // puts("flag_keygen activated!");
            kyber_keygen_raw();
        }
        else if (flag_encap) {
            // puts("flag_encap activated!");
            kyber_encapsulate_raw(key);
        }
        else if(flag_decap) {
            // puts("flag_decap activated!");
            kyber_decapsulate_raw(key, target);
        }
        else if(flag_encrypt) {
            // puts("flag_encrypt activated!");
            kyber_encrypt_raw(key, target);
        }
        else if(flag_decrypt) {
            // puts("flag_decrypt activated!");
            kyber_decrypt_raw(key, target);
        }
        else {
            fprintf(stderr, "err: no options activated\n");
        }
    }
    else if(flag_file) {

        if(flag_keygen) {
            // puts("flag_keygen activated!");
            kyber_keygen(result);
        }
        else if (flag_encap) {
            // puts("flag_encap activated!");
            kyber_encapsulate(key, result);
        }
        else if(flag_decap) {
            // puts("flag_decap activated!");
            kyber_decapsulate(key, target, result);
        }
        else if(flag_encrypt) {
            // puts("flag_encrypt activated!");
            kyber_encrypt(key, target, result);
        }
        else if(flag_decrypt) {
            // puts("flag_decrypt activated!");
            kyber_decrypt(key, target, result);
        }
        else {
            fprintf(stderr, "err: no options activated\n");
        }

    }
    

err:
    // puts("into err label");
    return 0;
}

// 내부 모듈이라 굳이 안쓰는게 나을지도?
void usage() {
    puts("usage: kmodule --keygen [key_length] [key_path] \
                 kmodule [file_path | raw_data] [-e | -d] -k [key_path] \
                 kmodule --encap [bob_puk] \
                 kmodule --decap [alice_prk]");
}

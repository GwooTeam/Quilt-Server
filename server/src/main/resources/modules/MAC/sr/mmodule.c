#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "nsc_api.h"
#include "mac_keygen.h"
#include "mac_sign.h"
#include "mac_verify.h"

#include "mac_keygen_raw.h"
#include "mac_sign_raw.h"
#include "mac_verify_raw.h"

int main(int argc, char* argv[]) {

    int option; // switch 대상 변수

    // flags
    unsigned int flag_keygen = 0;
    unsigned int flag_sign = 0;
    unsigned int flag_verify = 0;

    unsigned int flag_file = 0;
    unsigned int flag_raw = 0;

    // args. must be NULL.
    char* key = NULL;
    char* target = NULL;
    char* result = NULL;

    // strcut option의 배열 long_options[]
    // 여기는 긴 옵션 (--)들 설정
    // struct option { 옵션이름, 값 여부, 처리결과 플래그 포인터, 옵션 식별 정수(문자) }
    struct option long_options[] = {
        {"keygen", no_argument, &flag_keygen, 'a'}, // mac 키 생성
        {"hash", no_argument, &flag_sign, 'b'}, // mac 해시코드 생성
        {"verify", no_argument, &flag_verify, 'c'}, // mac 해시코드 검증

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

        // file based
        case 'f':
            flag_file = 1;
            break;

        // raw data based
        case 'r':
            flag_raw = 1;
            break;

        // 옵션 못 알아먹었을 때
        case '?':
            printf("into case ?\n");
            if (isprint(optopt)) {
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

    // puts("check paths");
    // printf("keypath: %s\n", key);
    // printf("target: %s\n", target);
    // printf("result: %s\n", result);
    int exit_code = 1;

    if(flag_file) {
        if(flag_keygen) {
            // puts("flag_keygen activated!");
            mac_keygen(result);
        }
        else if(flag_sign) {
            // puts("flag_sign activated!");
            if(key==NULL) {
                fprintf(stderr, "err: no key provided.\n");
                goto err;
            }
            if(target==NULL) {
                fprintf(stderr, "err: no data provided.\n");
                goto err;
            }
            exit_code = mac_sign(key, target, result);
        }
        else if(flag_verify) {
            puts("flag_verify activated!");
            exit_code = mac_verify(key, target, result);
        }
        else {
            fprintf(stderr, "err: no options activated\n");
        }

    } else if (flag_raw) {
        if(flag_keygen) {
            mac_keygen_raw();
            return 0;
        }
        else if(flag_sign) {
            if(key==NULL) {
                fprintf(stderr, "err: no key provided.\n");
                goto err;
            }
            if(target==NULL) {
                fprintf(stderr, "err: no data provided.\n");
                goto err;
            }
            exit_code = mac_sign_raw(key, target);
        }
        else if(flag_verify) {
            puts("flag_verify activated!");
            exit_code = mac_verify_raw(key, target, result);
        }
        else {
            fprintf(stderr, "err: no options activated\n");
        }
    }


err:
    // puts("into err label");
    if(flag_sign) {
        return exit_code;
    }
    if(flag_verify) {
        return exit_code;
    }
    return 1;

}
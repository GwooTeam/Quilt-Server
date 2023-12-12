#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "nc_api.h"
#include "dilithium.h"
#include "dilithium_raw.h"
#include "quilt_api.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("enter your option.\n");
        return 1;
    }

    // "--keygen" 옵션에 대한 동작 : public key와 private key 쌍 생성
    if (strcmp(argv[1], "--keygen") == 0) {
        if(strcmp(argv[2], "-r") == 0) {
            dilithium_keygen_raw();
        }
        else if (strcmp(argv[2], "-f") == 0) {
            dilithium_keygen();
        }
        else {
            puts("invalid option.");
        }
        // printf("option --keygen is selected. start generate key pair.\n");
        // printf("EOF\n");
    }

    // "-s" 옵션에 대한 동작 : 소유한 private key로 암호화하여 서명
    else if (strcmp(argv[1], "-s") == 0) {
        // printf("optiion -s is selected. start singing.\n");
        
        const char* data_path; // 세 번째 인자를 data_path 변수에 저장
        const char* prk_path;  // 네 번째 인자를 prk_path 변수에 저장

        // -r: raw 데이터를 입력받고 출력. -f: 파일 경로를 입력받고 결과 파일을 생성.
        if(strcmp(argv[2], "-r") == 0) {
            data_path = argv[3];
            prk_path = argv[4];
            dilithium_sign_raw(data_path, prk_path);
        }
        else if (strcmp(argv[2], "-f") == 0) {
            data_path = argv[3];
            prk_path = argv[4];
            dilithium_sign(data_path, prk_path);
        }
        else {
            puts("invalid option.");
        }
        // printf("EOF\n");
    }

     // "-v" 옵션에 대한 동작 : 소유한 public key로 서명 검증
    else if (strcmp(argv[1], "-v") == 0) {
        // printf("optiion -v is selected. start verification.\n");
        int res;
        const char* data_file_path;
        const char* signed_file_path; // 두 번째 인자를 signed_file_path 변수에 저장
        const char* puk_path; // 세 번째 인자를 prk_path 변수에 저장

        if(strcmp(argv[2], "-r") == 0) {
            data_file_path =  argv[3];
            signed_file_path = argv[4];
            puk_path = argv[5];
            res = dilithium_verify_raw(data_file_path, signed_file_path, puk_path);
        }
        else if (strcmp(argv[2], "-f") == 0) {
            res = dilithium_verify(data_file_path, signed_file_path, puk_path);
        }
        else {
            puts("invalid option.");
        }

        // printf("EOF\n");
        if(res == 0) {
            puts("success to verify.");
            return 0;
        }
        else return 1;
    }

    // 알 수 없는 옵션 처리
    else {
        printf("undefined opition. valid options are '--keygen','-s', and '-v'.\n");
        return 1;
    }

    return 0;
}

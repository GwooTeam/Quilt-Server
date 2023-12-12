#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "nsc_api.h"

void memfree(int, char*, char*); // deprecated

void kyber_keygen(const char* key_path) {

    NT_ULONG kg_type = NOB_CTX_KYBER_KEM_KEYPAIR_GEN; /* keygen type*/
    NT_ULONG enc_type = NOB_CTX_KYBER_KEM;            /* type*/

    NT_ULONG puk_type = NOB_PUBLIC_KEY;   /* public-key*/
    NT_ULONG prk_type = NOB_PRIVATE_KEY;  /* private-key*/
    NT_ULONG enc_data_type = NOB_DATA;    /* encrypted data type*/
    NT_ULONG level = NOP_KYBER_768;

    NT_CONTEXT keygenctx = {
        {NAT_OBJECT_TYPE, &kg_type, 0, FALSE, FALSE},
        {NAT_KYBER_SECURITY_LEVEL, &level, sizeof(level), FALSE, FALSE},
        {NAT_KYBER_IS_MATRIX_PRECOMPUTED, NULL, 0, FALSE, FALSE},
        {NAT_KYBER_SYMMETRIC_PRIMITIVE_TYPE, NULL, 0, FALSE, FALSE},
        {NAT_RANDOM_FUNCTION_TYPE, NULL, 0, FALSE, FALSE}};

    NT_OBJECT oPublicKey = {
        {NAT_OBJECT_TYPE, &puk_type, sizeof(puk_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, FALSE, FALSE}};

    NT_OBJECT oPrivateKey = {
        {NAT_OBJECT_TYPE, &prk_type, sizeof(prk_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, TRUE, FALSE}};

    // NT_CONTEXT kyberctx = {
    //     {NAT_OBJECT_TYPE, &enc_type, sizeof(enc_type), FALSE, FALSE},
    //     {NAT_KYBER_SECURITY_LEVEL, NULL, 0, FALSE, FALSE},
    //     {NAT_KYBER_IS_MATRIX_PRECOMPUTED, NULL, 0, FALSE, FALSE},
    //     {NAT_KYBER_SYMMETRIC_PRIMITIVE_TYPE, NULL, 0, FALSE, FALSE},
    //     {NAT_RANDOM_FUNCTION_TYPE, NULL, 0, FALSE, FALSE}};

    NT_RV ret;

    /**
     * Step 0. 모드 변경
     * 양자내성암호 모듈을 사용하기 위해 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL_PQC);
    // printf("current status = %d\n", NS_get_state());

    /**
     * Step 1. 키 쌍 생성
     * 캡슐화에 사용할 공개키(oPublicKey)와 디캡슐화에 사용할 개인키(oPrivateKey)를 생성한다.
     */
    puts("generating key pair...");
    if ((ret = NS_generate_keypair(&keygenctx,
                                   (NT_OBJECT_PTR)&oPublicKey,
                                   (NT_OBJECT_PTR)&oPrivateKey)) != NRC_OK)
    {
        printf("NS_generate_keypair failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    /* Print to ss1, ss2 */
    // NS_hex_dump(oPrivateKey[1].pValue, oPrivateKey[1].ulValueLen, (NT_BYTE_PTR) "private key");
    // NS_hex_dump(oPublicKey[1].pValue, oPublicKey[1].ulValueLen, (NT_BYTE_PTR) "public key");
    printf("\nsuccess keypair generate !!\n");

    // 키 쌍을 파일로 추출 (231107)
    char* prk_path = NULL;
    char* puk_path = NULL;
    int alloc_flag = 0;
    if(key_path) {
        size_t key_path_len = strlen(key_path);
        prk_path = calloc(key_path_len+20, 1);
        puk_path = calloc(key_path_len+20, 1);
        alloc_flag = 1;

        strncpy(prk_path, key_path, key_path_len);
        strncpy(puk_path, key_path, key_path_len);

        strcat(prk_path, "/kyber_key.prk");
        strcat(puk_path, "/kyber_key.puk");
    }
    else {
        prk_path = "kyber_key.prk";
        puk_path = "kyber_key.puk";
    }

    // 개인키 파일 생성
    FILE* pri_key_file;
    // printf("extracting private key to file..\n");
    pri_key_file = fopen(prk_path, "wb");
    if(pri_key_file == NULL) {
        printf("failed to create prk file.\n");
        goto err;
    }

    // NT_ULONG
    // NT_VOID_PTR
    // NT_ULONG
    // NT_BBOOL
    // NT_BBOOL

    fwrite(&oPrivateKey[1].type, sizeof(NT_ULONG), 1, pri_key_file);
    fwrite(&oPrivateKey[1].ulValueLen, sizeof(NT_ULONG), 1, pri_key_file);
    fwrite(oPrivateKey[1].pValue, oPrivateKey[1].ulValueLen, 1, pri_key_file);
    fwrite(&oPrivateKey[1].bSensitive, sizeof(NT_BBOOL), 1, pri_key_file);
    fwrite(&oPrivateKey[1].bAlloc, sizeof(NT_BBOOL), 1, pri_key_file);
    fclose(pri_key_file);
    puts("success to create private key!");



    // 공개키 파일 생성
    FILE* pub_key_file;
    // printf("extracting public key to file..\n");
    pub_key_file = fopen(puk_path, "wb");
    if(pub_key_file == NULL) {
        printf("failed to create puk file.\n");
        goto err;
    }

    // NT_ULONG
    // NT_VOID_PTR
    // NT_ULONG
    // NT_BBOOL
    // NT_BBOOL

    fwrite(&oPublicKey[1].type, sizeof(NT_ULONG), 1, pub_key_file);
    fwrite(&oPublicKey[1].ulValueLen, sizeof(NT_ULONG), 1, pub_key_file);
    fwrite(oPublicKey[1].pValue, oPublicKey[1].ulValueLen, 1, pub_key_file);
    fwrite(&oPublicKey[1].bSensitive, sizeof(NT_ULONG), 1, pub_key_file);
    fwrite(&oPublicKey[1].bAlloc, sizeof(NT_ULONG), 1, pub_key_file);
    fclose(pub_key_file);
    puts("success to create public key!");

    printf("puk length: %d\n", oPublicKey[1].ulValueLen);
    printf("prk length: %d\n", oPrivateKey[1].ulValueLen);

    printf("puk type: %d\n", oPublicKey[1].type);
    printf("puk len: %d\n", oPublicKey[1].ulValueLen);
    printf("puk alloc: %d\n", oPublicKey[1].bAlloc);
    printf("puk sensitive: %d\n", oPublicKey[1].bSensitive);

    printf("prk type: %d\n", oPrivateKey[1].type);
    printf("prk len: %d\n", oPrivateKey[1].ulValueLen);
    printf("prk alloc: %d\n", oPrivateKey[1].bAlloc);
    printf("prk sensitive: %d\n", oPrivateKey[1].bSensitive);

err:
    // puts("into err label");
    NS_clear_object(&oPublicKey, 2);
    NS_clear_object(&oPrivateKey, 2);


    if(alloc_flag) {
        free(prk_path);
        free(puk_path);
    }

}


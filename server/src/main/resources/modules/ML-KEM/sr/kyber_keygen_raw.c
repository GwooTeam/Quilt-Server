#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "nsc_api.h"
#include "quilt_api.h"

void kyber_keygen_raw() {

    NT_ULONG kg_type = NOB_CTX_KYBER_KEM_KEYPAIR_GEN; /* keygen type*/
    NT_ULONG enc_type = NOB_CTX_KYBER_KEM;            /* type*/

    NT_ULONG puk_type = NOB_PUBLIC_KEY;   /* public-key*/
    NT_ULONG prk_type = NOB_PRIVATE_KEY;  /* private-key*/
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
    if ((ret = NS_generate_keypair(&keygenctx,
                                   (NT_OBJECT_PTR)&oPublicKey,
                                   (NT_OBJECT_PTR)&oPrivateKey)) != NRC_OK)
    {
        fprintf(stderr, "NS_generate_keypair failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    /* Print to ss1, ss2 */
    // NS_hex_dump(oPrivateKey[1].pValue, oPrivateKey[1].ulValueLen, (NT_BYTE_PTR) "private key");
    // NS_hex_dump(oPublicKey[1].pValue, oPublicKey[1].ulValueLen, (NT_BYTE_PTR) "public key");
    // printf("\nsuccess keypair generate !!\n");


    /**
     * Step 2. 키 데이터 출력
     * 생성한 공개키와 개인키의 값을 표준 출력으로 출력.
     */

    printVal("puk=", (unsigned char*)oPublicKey[1].pValue, oPublicKey[1].ulValueLen);
    printVal("prk=", (unsigned char*)oPrivateKey[1].pValue, oPrivateKey[1].ulValueLen);

    
    // printf("puk length: %d\n", oPublicKey[1].ulValueLen);
    // printf("prk length: %d\n", oPrivateKey[1].ulValueLen);

    // printf("puk type: %d\n", oPublicKey[1].type);
    // printf("puk len: %d\n", oPublicKey[1].ulValueLen);
    // printf("puk alloc: %d\n", oPublicKey[1].bAlloc);
    // printf("puk sensitive: %d\n", oPublicKey[1].bSensitive);

    // printf("prk type: %d\n", oPrivateKey[1].type);
    // printf("prk len: %d\n", oPrivateKey[1].ulValueLen);
    // printf("prk alloc: %d\n", oPrivateKey[1].bAlloc);
    // printf("prk sensitive: %d\n", oPrivateKey[1].bSensitive);

err:
    // puts("into err label");
    NS_clear_object(&oPublicKey, 2);
    NS_clear_object(&oPrivateKey, 2);

}


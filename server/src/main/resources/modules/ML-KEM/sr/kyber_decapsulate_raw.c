#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

#include "quilt_api.h"

/// @brief Kyber768 Standard

/// - security level: Level 3
/// - matrix computation: No
/// - symmetric primitive: SHA3
/// - randomized signing: No

/* kyber encrypt module */
void kyber_decapsulate_raw(const char* prk_val, const char* capsule_val) {

    NT_ULONG enc_type = NOB_CTX_KYBER_KEM; /* type*/

    NT_ULONG prk_type = NOB_PRIVATE_KEY;  /* private-key*/
    NT_ULONG ss_type = NOB_SHARED_SECRET; /* shared secret*/
    NT_ULONG enc_data_type = NOB_DATA;    /* encrypted data type*/

    NT_OBJECT oPrivateKey = {
        {NAT_OBJECT_TYPE, &prk_type, sizeof(prk_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, TRUE, FALSE}};

    NT_CONTEXT kyberctx = {
        {NAT_OBJECT_TYPE, &enc_type, sizeof(enc_type), FALSE, FALSE},
        {NAT_KYBER_SECURITY_LEVEL, NULL, 0, FALSE, FALSE},
        {NAT_KYBER_IS_MATRIX_PRECOMPUTED, NULL, 0, FALSE, FALSE},
        {NAT_KYBER_SYMMETRIC_PRIMITIVE_TYPE, NULL, 0, FALSE, FALSE},
        {NAT_RANDOM_FUNCTION_TYPE, NULL, 0, FALSE, FALSE}};

    NT_OBJECT oEncryptedData = {
        {NAT_OBJECT_TYPE, &enc_data_type, sizeof(enc_data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, FALSE, FALSE}};

    NT_OBJECT oSharedSecret = {
        {NAT_OBJECT_TYPE, &ss_type, sizeof(ss_type), FALSE, FALSE},
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
     * step 1. 디캡슐화에 쓸 개인키 추출
     * 인자로 전달된 개인키를 oPrivateKey에 저장.
    */

    oPrivateKey[1].type = NAT_VALUE;

    oPrivateKey[1].pValue = (NT_VOID_PTR)calloc(2400, 1); // prk size 하드코딩
    hexToByte(prk_val, (unsigned char*)oPrivateKey[1].pValue, 2400);

    oPrivateKey[1].ulValueLen = 2400;
    oPrivateKey[1].bAlloc = TRUE;
    oPrivateKey[1].bSensitive = TRUE;

    // check private key
    // NS_hex_dump(oPrivateKey[1].pValue, oPrivateKey[1].ulValueLen, (NT_BYTE_PTR) "private key");



    /**
     * step 2. 캡슐 데이터 추출
     * 인자로 전달된 캡슐 데이터를 oEncryptedData에 저장.
    */

    size_t capsule_size = strlen(capsule_val) / 2;
    oEncryptedData[1].type = NAT_VALUE;

    oEncryptedData[1].pValue = (NT_VOID_PTR)calloc(capsule_size, 1);
    hexToByte(capsule_val, (unsigned char*)oEncryptedData[1].pValue, capsule_size);

    oEncryptedData[1].ulValueLen = capsule_size;
    oEncryptedData[1].bAlloc = FALSE;
    oEncryptedData[1].bSensitive = FALSE;


    /**
     * Step 3. 디캡슐화 초기작업
     */
    if ((ret = NS_decapsulate_init(&kyberctx,
                                   (NT_OBJECT_PTR)&oPrivateKey)) != NRC_OK)
    {
        fprintf(stderr, "NS_decapsulate_init failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }



    /**
     * Step 4. 디캡슐화
     * NS_decapsulate() 호출 전에 반드시 NS_decapsulate_init()로 초기 작업을 수행해야 한다.
     */

    // printf("start decapsulating..\n");
    if ((ret = NS_decapsulate(&kyberctx,
                              (NT_OBJECT_PTR)&oEncryptedData, // (NT_OBJECT_PTR)&oEncryptedData
                              (NT_OBJECT_PTR)&oSharedSecret)) != NRC_OK)
    {
        fprintf(stderr, "NS_decapsulate failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    // printf("decapsulate done.\n");

    /* Print to ss1 */
    // NS_hex_dump(oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen, (NT_BYTE_PTR) "shared secret1");


    
    /**
     * step 4. 디캡슐화한 데이터를 표준 출력으로 출력.
    */

    printVal("ssk=", (unsigned char*)oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen);


err:
    NS_clear_object(&oPrivateKey, 2);
    NS_clear_object(&oEncryptedData, 2);
    NS_clear_object(&oSharedSecret, 2);

}
#ifndef _KYBER_DECRYPT_RAW_H_
#define _KYBER_DECRYPT_RAW_H_

/* kyber 암호화 모듈 헤더파일 */
/* 대상 파일을 복호하여 result 경로에 저장 */
void kyber_decrypt_raw(const char* ssk_val, const char* cipher_val);

#endif
#ifndef _KYBER_DECRYPT_H_
#define _KYBER_DECRYPT_H_

/* kyber 암호화 모듈 헤더파일 */
/* 대상 파일을 복호하여 result 경로에 저장 */
void kyber_decrypt(const char* ssk_path, const char* cipher_path, const char* plain_path);

#endif
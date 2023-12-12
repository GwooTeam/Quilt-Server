#ifndef _KYBER_ENCRYPT_H_
#define _KYBER_ENCRYPT_H_

/* kyber 암호화 모듈 헤더파일 */
/* result 경로에 암호화한 파일을 생성 */
void kyber_encrypt(const char* ssk_path, const char* plain_path, const char* cipher_path);

#endif
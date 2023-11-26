#ifndef _QUILT_MAC_VERIFY_H_
#define _QUILT_MAC_VERIFY_H_

#include "nsc_api.h"

/* MAC 키를 활용하여 해시코드를 생성하는 함수 */
int mac_verify(const char* mackey_path, const char* data_path, const char* sign_path);

#endif
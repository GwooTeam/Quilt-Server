package com.gwooteam.server.auth;

public interface NodeAuthentication {

    Boolean signKeygen();
    // 서명 검증
    Boolean verifySign(String originFilePath, String signFilePath);
    // 무결성 검증
    Boolean verifyIntegrity(String originFilePath, String signFilePath);

}

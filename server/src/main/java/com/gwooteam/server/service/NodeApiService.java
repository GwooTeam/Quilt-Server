package com.gwooteam.server.service;

import com.gwooteam.server.auth.Certificates;
import com.gwooteam.server.auth.QuiltKey;

public interface NodeApiService {

    QuiltKey getServerDsaPubKey();

    byte[] generateNonce();

    Boolean verifyNode(Long id, String nodeSign, String nodeMac);

    Boolean saveNonce(Long id, byte[] nonce);

    Certificates generateCertificates(String pubK_encrypt, String pubK_sign, String publicIP);

}

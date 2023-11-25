package com.gwooteam.server.service;

import com.gwooteam.server.auth.Certificates;
import com.gwooteam.server.auth.QuiltKey;

public interface NodeApiService {

    QuiltKey getServerDsaPubKey();

    String generateNonce();

    Boolean verifyNode(Long id, String nodeSign, String nodeMac);

    Boolean saveNonce(Long id, String nonce);

    Certificates generateCertificates(String pubK_encrypt, String pubK_sign, String publicIP);

}

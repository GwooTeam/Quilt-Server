package com.gwooteam.server.service;

import com.gwooteam.server.auth.Certificates;
import com.gwooteam.server.auth.QuiltKey;

public interface NodeApiService {

    QuiltKey getMacKey();

    QuiltKey getServerKemPubKey();

    String generateNonce();

    String encapsulate();

    String decapsulate(Long id, String encapData);

    String encryptData(String sskVal, String originData);

    Boolean verifyNode(Long id, String nodeSign, String nodeMac);

    Boolean saveNonce(Long id, String nonce);

    Certificates generateCertificates(String pubK_encrypt, String pubK_sign, String publicIP);

}

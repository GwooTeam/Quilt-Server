package com.gwooteam.server.service;

import com.gwooteam.server.auth.Certificates;
import com.gwooteam.server.auth.QuiltKey;

public interface NodeApiService {

    QuiltKey getMacKey(Long id);

    QuiltKey getServerKemPubKey();

    String generateNonce();

    String encapsulate();

    String decapsulate(Long id, String encapData);

    String[] encryptData(String sskVal, String originData);

    Boolean verifyNode(Long id, String pukVal, String nodeSign, String nodeMac);

    Boolean saveNonce(Long id, String nonce);

    Boolean saveSerialNumber(Long id, String serialNum);

    Certificates generateCertificates(String pubK_encrypt, String pubK_sign, String publicIP);

}

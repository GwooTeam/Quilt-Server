package com.gwooteam.server.service;

import com.gwooteam.server.auth.*;
import com.gwooteam.server.auth.KeyAlgorithm;
import com.gwooteam.server.auth.KeyType;
import com.gwooteam.server.domain.Node;
import com.gwooteam.server.encryption.DataEncryption;
import com.gwooteam.server.repository.NodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.util.Random;

// @Service
@RequiredArgsConstructor
public class NodeApiServiceImpl implements NodeApiService {

    private final NodeRepository nodeRepository;
    private final NodeAuthentication nodeAuthentication;
    private final DataEncryption dataEncryption;

    @Override
    public QuiltKey getServerDsaPubKey() {
        QuiltKey key = new QuiltKey(KeyType.PUBLIC_KEY, KeyAlgorithm.ML_DSA);

        // 파일로부터 서버 key 읽어와야 함
        Resource resource = new ClassPathResource("modules/ML-DSA/dilithium_key.puk");
        try {
            byte[] pukData = FileCopyUtils.copyToByteArray(resource.getInputStream());
            key.setKeyLength(pukData.length);
            key.setKeyVal(pukData);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return key;
    }

    @Override
    public String generateNonce() {
        return generateRandom(10);
    }

    // Save Nonce
    @Transactional
    @Override
    public Boolean saveNonce(Long id, String nonce) {
        // nonce가 있다면 메서드 호출 못하도록 구현 필요
        Node node = nodeRepository.findOne(id);
        node.setNonce(nonce);
        nodeRepository.save(node);

        return Boolean.TRUE;
    }

    @Override
    public Boolean verifyNode(Long id, String nodeSign, String nodeMac) {
        // node가 보낸 sign과 mac을 검증하고 결과를 리턴한다.
        Node node = nodeRepository.findOne(id);
        String nonce = node.getNonce();

        // 서버의 개인키 추출
        // ServerKey prk = new ServerKey(KeyType.PRIVATE_KEY, KeyAlgorithm.ML_DSA);

        Boolean verifySignResult = nodeAuthentication.verifySign("originFile", nodeSign);
        Boolean macRes = verifyMac(nonce, nodeMac);

        return (verifySignResult && macRes);
    }

    @Override
    public Certificates generateCertificates(String pubK_encrypt, String pubK_sign, String publicIP) {

        String dsaSerial = generateRandom(10);
        String kemSerial = generateRandom(10);
        Certificates certificates = new Certificates(pubK_encrypt, pubK_sign, publicIP, dsaSerial, kemSerial);

        // 각 Certificate를 하나의 스트링으로 변환


        // Server Private Key로 서명


        // Init Certificates

        return certificates;
    }

    private static String generateRandom(Integer n) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder nonce = new StringBuilder();
        Random random = new Random();
        // int length = 10;
        for (int i = 0; i < n; i++) {
            int index = random.nextInt(characters.length());
            nonce.append(characters.charAt(index));
        }
        return nonce.toString();
    }

    // MAC 인증 로직
    private static Boolean verifyMac(String fetchNonce, String nodeMac) {

        // Server 측 MAC 계산
        String serverMac = "";

        if (nodeMac ==  serverMac) {
            return Boolean.TRUE;
        } else {
            return Boolean.FALSE;
        }
    }

}

package com.gwooteam.server.service;

import com.gwooteam.server.auth.*;
import com.gwooteam.server.auth.KeyAlgorithm;
import com.gwooteam.server.auth.KeyType;
import com.gwooteam.server.domain.Node;
import com.gwooteam.server.encryption.DataEncryption;
import com.gwooteam.server.kem.KeyCapsulation;
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
    private final KeyCapsulation keyCapsulation;
    private final DataEncryption dataEncryption;

    @Override
    public QuiltKey getMacKey() {
        QuiltKey key = new QuiltKey(KeyType.SECRET_KEY, KeyAlgorithm.MAC);
        key.setKeyVal(nodeAuthentication.generateMacKey());
        key.setKeyLength(32);
        return key;
    }

    @Override
    public QuiltKey getServerKemPubKey() {
        QuiltKey key = new QuiltKey(KeyType.PUBLIC_KEY, KeyAlgorithm.ML_KEM);

        // 파일로부터 서버 key 읽어와야 함
        Resource resource = new ClassPathResource("modules/ML-KEM/data/kyber_key.puk");
        try {
            byte[] pukData = FileCopyUtils.copyToByteArray(resource.getInputStream());
            key.setKeyLength(pukData.length);

            StringBuilder pukStr = new StringBuilder();
            for(byte b: pukData)
                pukStr.append(String.format("%02x", b));

            key.setKeyVal(pukStr.toString());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return key;
    }


    @Override
    public String generateNonce() {
        return generateRandomString(10);
    }

    @Override
    public String encapsulate() {
        String[] encapRes = keyCapsulation.encapsulate("serverPukVal");
        return encapRes[1]; // capsule 데이터만 리턴
    }

    @Override
    public String decapsulate(Long id, String encapData) {

        // get server prk
        String sskVal;
        Resource resource = new ClassPathResource("modules/ML-KEM/data/kyber_key.prk");
        try {
            // get server prk
            byte[] prkData = FileCopyUtils.copyToByteArray(resource.getInputStream());

            StringBuilder prkStrBuilder = new StringBuilder();
            for(byte b: prkData)
                prkStrBuilder.append(String.format("%02x", b));

            String prkStr = prkStrBuilder.toString();

            // decap
            sskVal = keyCapsulation.decapsulate(prkStr, encapData);

            // set ssk at node
            Node node = nodeRepository.findOne(id);
            node.setSsk(sskVal);
            return sskVal;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    @Override
    public String encryptData(String sskVal, String originData) {
        return dataEncryption.encrypt(sskVal, originData);
    }

    // Save Nonce
    @Transactional
    @Override
    public Boolean saveNonce(Long id, String nonce) {
        // nonce가 있다면 메서드 호출 못하도록 구현 필요

        // DB 부분. 별도 설정 필요.
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

        // 전달받은 sign과 mac을 파일로 생성하고 nodeAuth에 파일 경로를 전달한다.

        Boolean verifySignResult = nodeAuthentication.verifySign(id, "originFile", nodeSign);
        Boolean macRes = nodeAuthentication.verifyIntegrity(id, nonce, nodeMac);

        return (verifySignResult && macRes);
    }

    @Override
    public Certificates generateCertificates(String pubK_encrypt, String pubK_sign, String publicIP) {

        String dsaSerial = generateRandomString(10);
        String kemSerial = generateRandomString(10);
        Certificates certificates = new Certificates(pubK_encrypt, pubK_sign, publicIP, dsaSerial, kemSerial);

        // 각 Certificate를 하나의 스트링으로 변환


        // Server Private Key로 서명


        // Init Certificates

        return certificates;
    }

    private static String generateRandomString(Integer n) {
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



}

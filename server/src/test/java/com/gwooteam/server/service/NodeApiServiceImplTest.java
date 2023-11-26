//package com.gwooteam.server.service;
//
//import com.gwooteam.server.auth.KeyType;
//import com.gwooteam.server.auth.NodeAuthenticationImpl;
//import com.gwooteam.server.auth.QuiltKey;
//import com.gwooteam.server.repository.NodeRepository;
//import org.assertj.core.api.Assertions;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//
//import javax.persistence.EntityManager;
//
//class NodeApiServiceImplTest {
//
//    @Test
//    void getServerDsaPubKey() {
//        // given
//        QuiltKey key = nodeApiService.getServerDsaPubKey();
//
//        // when
//        byte[] keyVal = key.getKeyVal();
//
//        // then
//        for(byte b:keyVal) {
//            System.out.printf("%02X ", b);
//        }
//        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.PUBLIC_KEY);
//
//    }
//
//    @Test
//    void generateNonce() {
//        // given
//        String nonce = nodeApiService.generateNonce();
//
//        // when
//        System.out.println("nonce = " + nonce);
//
//        // then
//
//    }
//}
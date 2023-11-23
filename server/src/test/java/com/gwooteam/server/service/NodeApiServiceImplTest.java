package com.gwooteam.server.service;

import com.gwooteam.server.auth.KeyType;
import com.gwooteam.server.auth.MlDsaNodeAuthentication;
import com.gwooteam.server.auth.ServerKey;
import com.gwooteam.server.repository.NodeRepository;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.persistence.EntityManager;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class NodeApiServiceImplTest {

    @Autowired
    private NodeRepository nodeRepository;
    NodeApiService nodeApiService = new NodeApiServiceImpl(nodeRepository, new MlDsaNodeAuthentication());

    @Test
    void getServerDsaPubKey() {
        // given
        ServerKey key = nodeApiService.getServerDsaPubKey();

        // when
        byte[] keyVal = key.getKeyVal();

        // then
        for(byte b:keyVal) {
            System.out.printf("%02X ", b);
        }
        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.PUBLIC_KEY);

    }

    @Test
    void generateNonce() {
        // given
        String nonce = nodeApiService.generateNonce();

        // when
        System.out.println("nonce = " + nonce);

        // then

    }
}
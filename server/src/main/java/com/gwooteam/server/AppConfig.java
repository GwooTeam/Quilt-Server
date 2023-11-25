package com.gwooteam.server;

import com.gwooteam.server.auth.NodeAuthenticationImpl;
import com.gwooteam.server.auth.NodeAuthentication;
import com.gwooteam.server.encryption.DataEncryption;
import com.gwooteam.server.encryption.MlKemDataEncryption;
import com.gwooteam.server.integrity.Integrity;
import com.gwooteam.server.integrity.MacIntegrity;
import com.gwooteam.server.repository.NodeRepository;
import com.gwooteam.server.service.NodeApiService;
import com.gwooteam.server.service.NodeApiServiceImpl;
import com.gwooteam.server.service.NodeService;
import com.gwooteam.server.sign.DigitalSignature;
import com.gwooteam.server.sign.MldsaDigitalSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.persistence.Basic;
import javax.persistence.EntityManager;

@Configuration
public class AppConfig {

    private final EntityManager em;

    @Autowired
    public AppConfig(EntityManager em) {
        this.em = em;
    }

    @Bean
    public NodeRepository nodeRepository() {
        return new NodeRepository(em);
    }

    @Bean
    public DigitalSignature digitalSignature() {
        return new MldsaDigitalSignature();
    }

    @Bean
    public Integrity integrity() {
        return new MacIntegrity();
    }

    @Bean
    public DataEncryption dataEncryption() {
        return new MlKemDataEncryption();
    }

    @Bean
    public NodeAuthentication nodeAuthentication() {
        return new NodeAuthenticationImpl(digitalSignature(), integrity());
    }

    @Bean
    public NodeService nodeService() {
        return new NodeService(nodeRepository());
    }

    @Bean
    public NodeApiService nodeApiService() {
        return new NodeApiServiceImpl(nodeRepository(), nodeAuthentication(), dataEncryption());
    }

}

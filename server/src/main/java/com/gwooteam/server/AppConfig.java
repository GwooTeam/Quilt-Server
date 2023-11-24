package com.gwooteam.server;

import com.gwooteam.server.auth.MlDsaNodeAuthentication;
import com.gwooteam.server.auth.NodeAuthentication;
import com.gwooteam.server.repository.NodeRepository;
import com.gwooteam.server.service.NodeApiService;
import com.gwooteam.server.service.NodeApiServiceImpl;
import com.gwooteam.server.service.NodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
    public NodeAuthentication nodeAuthentication() {
        return new MlDsaNodeAuthentication();
    }

    @Bean
    public NodeService nodeService() {
        return new NodeService(nodeRepository());
    }

    @Bean
    public NodeApiService nodeApiService() {
        return new NodeApiServiceImpl(nodeRepository(), nodeAuthentication());
    }

}

package com.gwooteam.server.service;

import com.gwooteam.server.domain.Node;
import com.gwooteam.server.repository.NodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

// @Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class NodeService {

    private final NodeRepository nodeRepository;

    @Transactional
    public Long join(Node node) {
        // validate 필요
        this.nodeRepository.save(node);
        return node.getId();
    }

    private void validateDuplicateNode(Node node) {
        List<Node> findUsers = this.nodeRepository.findByHostname(node.getHostname());
        if(!findUsers.isEmpty()) {
            throw new IllegalStateException("Already Exists");
        }
    }

    public List<Node>findUsers() {
        return this.nodeRepository.findAll();
    }

    public Node findOne(Long id) {
        return this.nodeRepository.findOne(id);
    }



    // Save EncryptPubK, SignPubK
    @Transactional
    public void savePubKeys(Long id, String encryptPubK, String signPubK) {
        Node node = nodeRepository.findOne(id);
        node.setEncryptPubK(encryptPubK);
        node.setSignPubK(signPubK);
        this.nodeRepository.save(node);
    }
}

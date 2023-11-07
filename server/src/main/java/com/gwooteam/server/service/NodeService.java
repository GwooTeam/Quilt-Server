package com.gwooteam.server.service;

import com.gwooteam.server.domain.Node;
import com.gwooteam.server.repository.NodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
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

    @Transactional
    public void saveNonce(Long id, String nonce) {
        // nonce가 있다면 메서드 호출 못하도록 구현 필요
        Node node = nodeRepository.findOne(id);
        node.setNonce(nonce);
        this.nodeRepository.save(node);
    }
}

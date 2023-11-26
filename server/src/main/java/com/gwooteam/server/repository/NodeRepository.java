package com.gwooteam.server.repository;

import com.gwooteam.server.domain.Node;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import java.util.List;

// @Repository
// @RequiredArgsConstructor
public class NodeRepository {

    private final EntityManager em;

    public NodeRepository(EntityManager em) {
        this.em = em;
    }

    public void save(Node node) { this.em.persist(node); }

    public Node findOne(Long id) { return (Node)this.em.find(Node.class, id); }

    public List<Node> findAll() {
        return this.em.createQuery("select n from Node n", Node.class).getResultList();
    }

    public List<Node> findByHostname(String hostname) {
        return this.em.createQuery("select n from Node n where n.hostname = :hostname", Node.class).setParameter("hostname", hostname).getResultList();
    }

    public Node findByID(String nodeID) {
        try {
            return this.em.createQuery("select n from Node n where n.nodeID = :nodeID", Node.class)
                    .setParameter("nodeID", nodeID)
                    .getSingleResult();
        } catch (NoResultException e) {
            // 결과가 없을 때의 처리. 예를 들어 null 반환
            return null;
        }
    }
}

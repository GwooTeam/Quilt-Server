package com.gwooteam.server.repository;

import com.gwooteam.server.domain.Node;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
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
        return this.em.createQuery("select n from Node n where n.nodeID = :nodeID", Node.class).setParameter("nodeID", nodeID).getSingleResult();
    }
}

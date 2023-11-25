package com.gwooteam.server.controller;

import com.gwooteam.server.domain.Node;
import com.gwooteam.server.service.NodeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class NodeController {

    private final NodeService nodeService;

    @GetMapping("/nodes/new")
    public String createNode(Model model) {
        model.addAttribute("form", new NodeForm());
        return "nodes/createNodeForm";
    }

    @PostMapping("/nodes/new")
    public String create(NodeForm form) {
        Node node = new Node();
        node.setHostname(form.getHostname());
        node.setPublicIP(form.getIp());
        node.setNodeID(form.getNodeID());
        node.setNodePW(form.getNodePW());

        nodeService.join(node);
        return "redirect:/nodes";
    }

    @GetMapping("/nodes")
    public String list(Model model) {
        List<Node> nodes = this.nodeService.findUsers();
        model.addAttribute("nodes", nodes); // test
        return "nodes/nodeList";
    }

}

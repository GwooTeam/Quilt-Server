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

    @PostMapping("/nodes/new")
    public void create(@RequestBody Node node) {
//        User newUser = new User(user.getId(), user.getHostname(), user.getId());
        nodeService.join(node);
    }

    @GetMapping("/nodes")
    public String list(Model model) {
        List<Node> nodes = this.nodeService.findUsers();
        model.addAttribute("nodes", nodes); // test
        return "nodes/nodeList";
    }
}

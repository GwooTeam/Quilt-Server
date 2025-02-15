package com.gwooteam.server.login;

import com.gwooteam.server.controller.NodeForm;
import com.gwooteam.server.domain.Node;
import com.gwooteam.server.service.NodeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final NodeService nodeService;
    private static Logger logger = LoggerFactory.getLogger(LoginController.class);

    @GetMapping("/nodes/login")
    public String loginNode(Model model) {
        model.addAttribute("form", new LoginForm());
        return "nodes/loginNodeForm";
    }

    @PostMapping("/nodes/login")
    public String login(LoginForm form) {
        Node node = nodeService.findByID(form.getNodeID());
        if (node == null) {
            return "/nodes/loginNodeErrorForm";
        }

        if (node.getNodePW().equals(form.getNodePW())) {
            return "redirect:/nodes";
        } else {
            return "nodes/loginNodeErrorForm";
        }
    }

}

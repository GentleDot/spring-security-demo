package net.gentledot.demospringsecurity.account.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AccessDeniedControler {
    @GetMapping("/access-denied")
    public String notifyAccessDenied(Model model, Principal principal) {
        model.addAttribute("name", principal.getName());
        return "sample/access-denied";
    }
}
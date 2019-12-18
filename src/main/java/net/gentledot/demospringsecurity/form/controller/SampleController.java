package net.gentledot.demospringsecurity.form.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class SampleController {

    @GetMapping("/")
    public String index(Model model, Principal principal){
        String message = "Hello, Spring Security.";
        if (principal != null){
            message = "Hello, " + principal.getName();
        }

        model.addAttribute("message", message);
        return "index";
    }

    @GetMapping("/info")
    public String info(Model model){
        model.addAttribute("message", "Hello, this is info page");
        return "sample/info";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal){
        model.addAttribute("message", "Hello, " + principal.getName());
        return "sample/dashboard";
    }

    @GetMapping("/admin")
    public String admin(Model model, Principal principal){
        model.addAttribute("message", "Hello, " + principal.getName() + "You Have Admin Role.");
        return "sample/admin";
    }

}

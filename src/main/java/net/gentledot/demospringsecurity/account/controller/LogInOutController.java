package net.gentledot.demospringsecurity.account.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LogInOutController {

    @GetMapping("/userLogin")
    public String loginForm(){
        return "sample/login";
    }

    @GetMapping("/userLogout")
    public String logoutPage(){
        return "sample/logout";
    }
}
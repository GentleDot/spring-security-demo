package net.gentledot.demospringsecurity.form.controller;

import net.gentledot.demospringsecurity.account.service.SampleService;
import net.gentledot.demospringsecurity.common.SecurityLogger;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.concurrent.Callable;

@Controller
public class SampleController {

    private final SampleService sampleService;

    public SampleController(SampleService sampleService) {
        this.sampleService = sampleService;
    }

    @GetMapping("/")
    public String index(Model model, Principal principal) {
        String message = "Hello, Spring Security.";
        if (principal != null) {
            message = "Hello, " + principal.getName();
        }

        model.addAttribute("message", message);
        return "index";
    }

    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute("message", "Hello, this is info page");
        return "sample/info";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello, " + principal.getName());
        sampleService.dashboard();
        return "sample/dashboard";
    }

    @GetMapping("/admin")
    public String admin(Model model, Principal principal) {
        model.addAttribute("message", "Hello, " + principal.getName() + "! You are logged in as Admin.");
        return "sample/admin";
    }

    @GetMapping("/user")
    public String user(Model model, Principal principal) {
        model.addAttribute("message", "Hello, User. " + principal.getName());
        return "sample/user";
    }

    // SecurityContext = threadLocal / async = 다른 thread 사용
    // WebAsyncManagerIntegrationFilter : async 환경에서도 동일한 SecurityContext를 사용할 수 있도록 지원하는 필터
    @GetMapping("/async-handler")
    @ResponseBody
    public Callable<String> asyncHandler() {
        // tomcat이 할당한 NIO thread
        SecurityLogger.log("===MVC===");

        // request를 처리하는 thread를 반환하고 Callable에서의 처리가 완료되면 그 응답을 보냄.
        return () -> {
            // 별도의 thread
            SecurityLogger.log("===Callable===");
            return "Async Handler";
        };
    }

}

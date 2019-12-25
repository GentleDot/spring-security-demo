package net.gentledot.demospringsecurity.account.service;

import net.gentledot.demospringsecurity.account.domain.Account;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SampleServiceTest {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountService accountService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Test
    public void dashboard() {
        String username = "test";
        String password = "test1";
        String role = "USER";
        Account account = createUser(username, password, role);

        UserDetails principal = accountService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal, password);
        Authentication authentication = authenticationManager.authenticate(token);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        sampleService.dashboard();
    }

    @Test
    @WithMockUser(username = "test", password = "test1", roles = "USER")
    public void dashboardTestUsingMockUser() {
        sampleService.dashboard();
    }

    private Account createUser(String username, String password, String roleStr) {
        Account account = Account.builder()
                .username(username)
                .password(password)
                .role(roleStr)
                .build();

        accountService.createUser(account);
        return account;
    }
}
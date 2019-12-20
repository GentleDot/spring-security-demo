package net.gentledot.demospringsecurity.account.controller;

import net.gentledot.demospringsecurity.account.domain.Account;
import net.gentledot.demospringsecurity.account.service.AccountService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AccountService accountService;

    @Test
    @WithAnonymousUser
    public void requestIndexByAnonymous() throws Exception {
        // given

        // when
//        ResultActions actions = mockMvc.perform(get("/").with(anonymous()));
        ResultActions actions = mockMvc.perform(get("/"));

        // then
        actions.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "test", roles = "USER")
    public void requestIndexByUser() throws Exception {
        // given
//        String username = "test";

        // when
        // test 유저가 로그인 한 상태를 가정
//        ResultActions actions = mockMvc.perform(get("/").with(user(username).roles("USER")));
        ResultActions actions = mockMvc.perform(get("/"));

        // then
        actions.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void requestAdminPageByUserWithForbidden() throws Exception {
        // given
        String username = "test";

        // when
        ResultActions actions = mockMvc.perform(get("/admin").with(user(username).roles("USER")));

        // then
        actions.andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void requestAdminPageByAdmin() throws Exception {
        // given
//        String username = "admin";

        // when
//        ResultActions actions = mockMvc.perform(get("/admin").with(user(username).roles("ADMIN")));
        ResultActions actions = mockMvc.perform(get("/admin"));

        // then
        actions.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @Transactional
    public void loginSuccess() throws Exception {
        // given
        String username = "test";
        String password = "123";

        Account account = createUser(username, password);

        // when
        ResultActions actions = mockMvc.perform(formLogin().user(username).password(password));

        // then
        actions.andDo(print())
                .andExpect(authenticated());
    }

    @Test
    @Transactional
    public void loginFailed() throws Exception {
        // given
        String username = "test";
        String password = "123";

        Account account = createUser(username, password);

        // when
        ResultActions actions = mockMvc.perform(formLogin().user(username).password("1234qwer"));

        // then
        actions.andDo(print())
                .andExpect(unauthenticated());
    }

    @Test
    public void sampleAuthentication() throws Exception {
        String username = "test";
        String password = "123";

        Account account = createUser(username, password);

        ResultActions actions = mockMvc.perform(get("/dashboard"));
    }

    private Account createUser(String username, String password) {
        Account account = Account.builder()
                .username(username)
                .password(password)
                .role("USER")
                .build();
        return accountService.createUser(account);
    }
}
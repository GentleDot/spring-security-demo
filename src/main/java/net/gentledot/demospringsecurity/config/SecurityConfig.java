package net.gentledot.demospringsecurity.config;

import net.gentledot.demospringsecurity.account.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountService accountService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 설정
        http.anonymous()
                .and()
                .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
                .expressionHandler(expressionHandler());
//                .accessDecisionManager(accessDecisionManager());
                /*
                .and()
                .formLogin()
                .and()
                .httpBasic();
                */

        // form login 설정
        http.formLogin();
        // http의 basic oauth ??
        http.httpBasic();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().mvcMatchers("/favicon.ico");
    }

    //    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        // 크게 inMemory, jdbc, ldap Authentication 사용 가능
//        // {noop} : 암호화 방식 없음 (encoder 없음)
//        auth.inMemoryAuthentication()
//                .withUser("gentledot")
//                    .password("{noop}123").roles("USER")
//                .and()
//                .withUser("admin").password("{noop}!@#").roles("ADMIN");
//    }
//
//    @Bean
//    @Override
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(accountService);
    }

    /*
    private AccessDecisionManager accessDecisionManager() {

        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        webExpressionVoter.setExpressionHandler(handler);

//        List<AccessDecisionVoter<?>> voters = Arrays.asList(webExpressionVoter);
        List<AccessDecisionVoter<?>> voters = Collections.singletonList(webExpressionVoter);
        return new AffirmativeBased(voters);
    }
    */


    //    private SecurityExpressionHandler expressionHandler() {
    private SecurityExpressionHandler<FilterInvocation> expressionHandler() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        return handler;
    }


}

package net.gentledot.demospringsecurity.config;

import net.gentledot.demospringsecurity.account.service.AccountService;
import net.gentledot.demospringsecurity.common.AccessDeniedLogger;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final AccountService accountService;
    private final AccessDeniedLogger accessDeniedLogger;

    public SecurityConfig(AccountService accountService, AccessDeniedLogger accessDeniedLogger) {
        this.accountService = accountService;
        this.accessDeniedLogger = accessDeniedLogger;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().mvcMatchers("/favicon.ico");
//        web.ignoring().requestMatchers(PathRequest.toStaticResources().at());
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 설정
//        http.anonymous()
//                .and()
                http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
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
        http.formLogin()
                .loginPage("/userLogin")
                .permitAll()
            .and()
            .logout()
                .logoutUrl("/userLogout")
                .logoutSuccessUrl("/")
            .and()
            .headers(); // headers() 를 통해 브라우저가 더 이상 페이지를 캐시하지 않음.

        // http의 basic oauth ??
        http.httpBasic();

        http.exceptionHandling()
//                .accessDeniedPage("/access-denied");
            .accessDeniedHandler(accessDeniedLogger.deniedHandle());

        http.rememberMe()
                .userDetailsService(accountService)
                .key("remember-me-sample");
//                .rememberMeParameter("rememberParam") // default = remember-me
//                .tokenValiditySeconds() // default = 2주
//                .useSecureCookie() // HTTPS 접근만 쿠키 사용이 가능하도록 설정
//                .alwaysRemember()   // default = false

        // 하위 Thread에게 ContextHolder가 공유되도록 설정
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
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
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


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

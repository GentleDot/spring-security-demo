# Spring Security 학습

## 목차
- [목표](#목표)
- [참고자료](#참고자료)
- [학습내용](#학습내용)
    - [demo project](#demo-project)
    - [Spring Security 연동](#Spring-Security-연동)
        - [의존성 추가](#Spring-Security-의존성-추가)
        - [설정 추가](#Spring-Web-Security-설정-추가)
        - [커스터마이징 : inMemory User](#Customizing_inMemory-User-추가)
        - [커스터마이징 : JPA 연동하여 User 생성](#Customizing_JPA-연동)
        - [커스터마이징 : PasswordEncoder](#Customizing_PasswordEncoder)
    - [Spring Security Architecture](#Spring-Security-Architecture)
        - [SecurityContextHolder와 Authentication의 위치](#SecurityContextHolder와-Authentication)
        - [AuthenticationManager와 Authentication](#AuthenticationManager와-Authentication)
        - [ThreadLocal](#ThreadLocal)
        - [Spring Security Filter와 FilterChainProxy](#Spring-Security-Filter와-FilterChainProxy)
        - [AccessControl(Authorization)](#AccessControl(Authorization))
        - [FilterSecurityInterceptor](#FilterSecurityInterceptor)
        - [Architecture 정리](#Architecture-정리)
        
## 목표
1. Spring Security Form 인증 학습
1. Spring Security의 아키텍쳐 확인
1. Web Application Security 정리
1. thymeleaf로 view 생성 방식 정리 (간단정리)

## 참고자료
- 문서 :
    - [Gradle User Guide #Managing your dependencies](https://docs.gradle.org/current/userguide/building_java_projects.html#sec:java_dependency_management_overview)
    - [Gradle 빌드시스템 기초](https://effectivesquid.tistory.com/entry/Gradle-%EB%B9%8C%EB%93%9C%EC%8B%9C%EC%8A%A4%ED%85%9C-%EA%B8%B0%EC%B4%88)
    - [spring-security 5.0 에서 달라진 암호변환정책](https://java.ihoney.pe.kr/498)
    - [Spring Password Encoder](https://gompangs.tistory.com/entry/Spring-Password-Encoder)
    - [자바 커스텀 어노테이션 만들기](https://advenoh.tistory.com/21)
    
- 강의 :
    - [스프링 시큐리티 / 백기선](https://www.inflearn.com/course/%EB%B0%B1%EA%B8%B0%EC%84%A0-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0/lecture/22894)  


## 학습내용

### demo project
- 4개의 뷰 생성
    1. 홈페이지
        - GET '/'
        - 인증된 사용자도 접근할 수 있으며 인증하지 않은 사용자도 접근할 수 있습니다.
        - 인증된 사용자가 로그인 한 경우에는 이름을 출력할 것.
    
    1. 정보
        - GET '/info'
        - 이 페이지는 인증을 하지 않고도 접근할 수 있으며, 인증을 한 사용자도 접근할 수 있습니다.
    
    1. 대시보드
        - GET '/dashboard'
        - 이 페이지는 반드시 로그인 한 사용자만 접근할 수 있습니다.
        - 인증하지 않은 사용자가 접근할 시 로그인 페이지로 이동합니다.
    
    1. 어드민
        - GET '/admin'
        - 이 페이지는 반드시 ADMIN 권한을 가진 사용자만 접근할 수 있습니다.
        - 인증하지 않은 사용자가 접근할 시 로그인 페이지로 이동합니다.
        - 인증은 거쳤으나, 권한이 충분하지 않은 경우 에러 메시지를 출력합니다.

- Spring Boot Web App 생성
    - 의존성 설정
        - web-start
        - thymeleaf
    
    - 4개 view를 핸들링할 수 있는 controller 생성
    
    - thymeleaf
        - xmlns:th=”​http://www.thymeleaf.org​” 네임스페이스를 html 태그에 추가.
        - th:text=”${message}” 사용해서 Model에 들어있는 값 출력 가능.
        
        ```
        <!DOCTYPE html>
        <html lang="kr" xmlns:th="http://www.thymeleaf.org">
        <head>
            <meta charset="UTF-8">
            <title>Title</title>
        </head>
        <body>
            <h1 th:text="${message}">Hello World!</h1>
        </body>
        </html>
        ```

- 현재의 문제
    - 로그인할 방법이 없음.
    - 현재 사용자를 알아낼 방법 없음.
    

### Spring Security 연동

#### Spring Security 의존성 추가
- Starter 사용
    - version 생략 (Spring Boot의 의존성 관리 기능 사용)
    
    ```
    // pom.xml
    <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    // build.gradle
    implementation 'org.springframework.boot:spring-boot-starter-security'
    ```

- 의존성 추가 후 App을 Run 시키면?
    - 모든 요청은 인증을 필요로 하게 됨.
    - 기본 유저가 생성됨.
        - username : user
        - password : 실행시 마다 변경되어 log에 출력됨.
            
            ```
            2019-12-18 22:20:30.164  INFO 23076 --- [  restartedMain] .s.s.UserDetailsServiceAutoConfiguration : 
            Using generated security password: 9b292567-72c2-4a74-b68e-f9f1b72da0f2
            ```

- 현재의 문제
    - 인증을 사용할 수 있고 현재 사용자 정보를 알 수 있게 되었지만
    - 인증 없이 접근 가능한 URL 설정이 필요
    - 계정이 user 하나 뿐이고
    - 비밀번호가 log에 출력되는 상태 


#### Spring Web Security 설정 추가

```
package net.gentledot.demospringsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 설정
        http.anonymous()
                .and()
                .authorizeRequests()
                .mvcMatchers("/", "/info").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated();
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
}
```

- 현재상태
    - 요청 URL별 인증 설정 완료
    - '/', '/info'는 로그인 없이 접속 가능
    - 계정은 여전히 하나뿐
    - ADMIN 계정(ADMIN Role) 없음
    - 비밀번호가 여전히 로그에 출력되고 있음


#### Customizing_inMemory User 추가
- 스프링 부트가 만들어 주던 유저 정보는?
    - UserDetailsServiceAutoConfiguration
    - SecurityProperties

- SecurityConfig class에 다음 설정 추가
    - inMemory 사용자 추가
    - local AuthenticationManager를 bean으로 노출
    
    ```
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 크게 inMemory, jdbc, ldap Authentication 사용 가능
        // {noop} : 암호화 방식 없음 (encoder 없음)
        auth.inMemoryAuthentication()
                .withUser("gentledot")
                    .password("{noop}123").roles("USER")
                .and()
                .withUser("admin").password("{noop}!@#").roles("ADMIN");
    }
    
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    ```

- 현재상태
    - 계정 생성 가능
    - ADMIN role을 설정한 유저 추가
    - 비밀번호가 소스 코드내 있음
    - DB에 있는 유저 정보 사용하려면?

#### Customizing_JPA 연동
- Spring Data JPA, H2DB 의존성 추가
    ```
    // pom.xml
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
  
    // build.gradle
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    developmentOnly 'com.h2database:h2'
    ```

- Account class (DAO 또는 Domain)
    ```
    package net.gentledot.demospringsecurity.account.domain;
    
    import lombok.*;
    
    import javax.persistence.Column;
    import javax.persistence.Entity;
    import javax.persistence.GeneratedValue;
    import javax.persistence.Id;
    
    @Entity
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Setter
    @EqualsAndHashCode(of = "id")
    public class Account {
        @Id
        @GeneratedValue
        private Integer id;
    
        @Column(unique = true)
        private String username;
    
        private String password;
    
        private String role;
    
        public void encodePassword() {
            this.password = "{noop}" + this.password;
        }
    }
    ```
  
- AccountRepository Interface
    ```
    package net.gentledot.demospringsecurity.account.repository;
    
    import net.gentledot.demospringsecurity.account.domain.Account;
    import org.springframework.data.jpa.repository.JpaRepository;
    import org.springframework.stereotype.Repository;
    
    @Repository
    public interface AccountRepository extends JpaRepository<Account, Integer> {
        Account findByUsername(String username);
    }
    ```

- AccountService Class implements UserDetailsService
    ```
    package net.gentledot.demospringsecurity.account.service;
    
    import net.gentledot.demospringsecurity.account.domain.Account;
    import net.gentledot.demospringsecurity.account.repository.AccountRepository;
    import org.springframework.security.core.userdetails.User;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.stereotype.Service;
    
    @Service
    public class AccountService implements UserDetailsService {
    
        // TODO {noop}123
        private final AccountRepository accountRepository;
    
        public AccountService(AccountRepository accountRepository) {
            this.accountRepository = accountRepository;
        }
    
        // username을 받아 해당하는 user 정보를 가져와 UserDetails로 return
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            Account account = accountRepository.findByUsername(username);
    
            if (username == null) {
                throw new UsernameNotFoundException(username);
            }
    
            return User.builder()
                    .username(account.getUsername())
                    .password(account.getPassword())
                    .roles(account.getRole())
                    .build();
        }
    
        public Account createUser(Account account) {
            account.encodePassword();
            return  accountRepository.save(account);
        }
    }
    ```

- AccountController
    - Account 생성 요청을 Handing
    
    ```
    package net.gentledot.demospringsecurity.account.controller;
    
    import net.gentledot.demospringsecurity.account.domain.Account;
    import net.gentledot.demospringsecurity.account.service.AccountService;
    import org.springframework.web.bind.annotation.GetMapping;
    import org.springframework.web.bind.annotation.ModelAttribute;
    import org.springframework.web.bind.annotation.RestController;
    
    @RestController
    public class AccountController {
    
        private final AccountService accountService;
    
        public AccountController(AccountService accountService) {
            this.accountService = accountService;
        }
    
        @GetMapping("/account/{role}/{username}/{password}")
        public Account createAccount(@ModelAttribute Account account){
            return accountService.createUser(account);
        }
    }
    ```

#### Customizing_PasswordEncoder
- 비밀번호는 단방향 암호화 알고리즘으로 encoding 하여 저장
    
    출처 : [Spring Password Encoder](https://gompangs.tistory.com/entry/Spring-Password-Encoder)  
    >아, 그 전에 패스워드를 저장할 때 사용하는 알고리즘을 먼저 봐야 하는데 일단 패스워드는 무조건 단방향 암호화/해싱을 사용해야 한다.  
      한번 encode된 패스워드는 다시 복호화를 할 수 없도록 해야 하고(AES,RSA,DES… 등의 양방향 암호화를 사용하면 안된다는 뜻이다) 이를 비교하는 로직만 같은지 아닌지만 판단할 수 있게 만들어야 한다.  
      이를 지키지 않을 경우 최악은 DB에 저장된 유저의 패스워드가 다 복호화 되어 개인정보가 털리던.. 혹은 결제와 관련된 경우 직접적인 타격을 받게될 수도 있다.  
      혹여나, 지금이라도 패스워드를 AES 등으로 저장하여 사용하고 있다면 당장 해싱하는 방향으로 바꾸도록 하자

- {id}encodedPassword  

    > 출처: 허니몬(Honeymon)의 자바guru  
     [spring-security 5.0 에서 달라진 암호변환정책](https://java.ihoney.pe.kr/498)
       
- 다양한 hashing 전략의 Password 지원

- 이전 Noop 방식 (비추천!)
    ```
    @Bean
    public PasswordEncoder passwordEncoder(){
        // 비밀번호가 평문 그대로 저장 (비추천!) (Spring 4 이전)
        return NoOpPasswordEncoder.getInstance();
    }
    ```

- PasswordEncoderFactories 사용 (기본 : bcrypt로 암호화)
    ```
    package net.gentledot.demospringsecurity.config;
    
    import org.springframework.cglib.proxy.NoOp;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.crypto.factory.PasswordEncoderFactories;
    import org.springframework.security.crypto.password.NoOpPasswordEncoder;
    import org.springframework.security.crypto.password.PasswordEncoder;
    
    @Configuration
    public class AppConfig {
        @Bean
        public PasswordEncoder passwordEncoder(){
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }
    }
    ```
  
    - AccountService 암호화 방식 변경 (하드코딩 부분 변경)
    ```
    public Account createUser(Account account) {
        account.encodePassword(passwordEncoder);
        return  accountRepository.save(account);
    }
    ```
    ```
    public void encodePassword(PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(this.password);
    }
    ```

- 현재상태
    - {noop}을 제거함.
        ```
        /* http://localhost:8080/account/USER/test1/test123 */
        {"id":2,"username":"test1","password":"{bcrypt}$2a$10$n5KBvFFQl.5eKAlM2cewOuItLuWIYLFzBWBKRTZCFqE91uZNfQ22G","role":"USER"}
        ```
      
#### Spring Security Test
- 의존성 추가  (테스트에서 사용할 기능을 제공)
```
// pom.xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>

// build.gradle
testImplementation 'org.springframework.security:spring-security-test'
```

```
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

        // when
        ResultActions actions = mockMvc.perform(get("/admin"));
        // then
        actions.andDo(print())
                .andExpect(status().isOk());
    }
```

- RequestPostProcessor를 사용해서 테스트
    - with(user(“user”))
    - with(anonymous())
    - with(user(“user”).password(“123”).roles(“USER”, “ADMIN”))

- Annotation 사용
    - @WithMockUser
    - @WithMockUser(roles=”ADMIN”)
    - 커스텀 애노테이션을 만들어 재사용 가능.

- Form Login / Logout
    - perform(formLogin())
    - perform(formLogin().user("admin").password("pass"))
    - perform(logout())

- form login의 응답 유형 확인
    - authenticated()
    - unauthenticated()

```
package net.gentledot.demospringsecurity.account.controller;

import net.gentledot.demospringsecurity.account.domain.Account;
import net.gentledot.demospringsecurity.account.service.AccountService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

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

    private Account createUser(String username, String password) {
        Account account = Account.builder()
                .username(username)
                .password(password)
                .role("USER")
                .build();
        return accountService.createUser(account);
    }
}
```

### Spring Security Architecture

> 출처 : [스프링 시큐리티 / 백기선](https://www.inflearn.com/course/%EB%B0%B1%EA%B8%B0%EC%84%A0-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0/lecture/22894)   
![Spring Security Architecture](img/security_architecture.jpg "스프링 시큐리티의 구조")


#### SecurityContextHolder와 Authentication

```
package net.gentledot.demospringsecurity.account.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {
    public void dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Object credentials = authentication.getCredentials();
        boolean authenticated = authentication.isAuthenticated();
    }
}
```

```
// authentication
authentication = {UsernamePasswordAuthenticationToken@10822} "org.springframework.security.authentication.UsernamePasswordAuthenticationToken@428ccf1b: Principal: org.springframework.security.core.userdetails.User@6924ddf: Username: test1; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER; Credentials: [PROTECTED]; Authenticated: true; Details: org.springframework.security.web.authentication.WebAuthenticationDetails@380f4: RemoteIpAddress: 0:0:0:0:0:0:0:1; SessionId: 912325EFB6D771F9DC1B9543A8820917; Granted Authorities: ROLE_USER"
principal = {User@10825} "org.springframework.security.core.userdetails.User@6924ddf: Username: test1; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER"
credentials = null
authorities = {Collections$UnmodifiableRandomAccessList@10828}  size = 1
details = {WebAuthenticationDetails@10833} "org.springframework.security.web.authentication.WebAuthenticationDetails@380f4: RemoteIpAddress: 0:0:0:0:0:0:0:1; SessionId: 912325EFB6D771F9DC1B9543A8820917"
authenticated = true

// principal
principal = {User@10825} "org.springframework.security.core.userdetails.User@6924ddf: Username: test1; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER"
password = null
username = "test1"
authorities = {Collections$UnmodifiableSet@10837}  size = 1
accountNonExpired = true
accountNonLocked = true
credentialsNonExpired = true
enabled = true

// authorities
authorities = {Collections$UnmodifiableRandomAccessList@10828}  size = 1
0 = {SimpleGrantedAuthority@10839} "ROLE_USER"
role = "ROLE_USER"
value = {byte[9]@10841} 
coder = 0
hash = -1142751756
```

- SecurityContextHolder
    ![SecurityContextHolder](img/security_context_holder.jpg "SecurityContextHolder 구조")
    
    - SecurityContext 제공, 기본적으로 ThreadLocal을 사용한다.
    - SecurityContext는 Authentication를 제공

- Authentication
    - Principal
    - GrantAuthority

- Principal
    - “누구"에 해당하는 정보.
    - UserDetailsService에서 리턴한 그 객체.
        ```
        // net.gentledot.demospringsecurity.config
        @Autowired
        AccountService accountService;
    
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(accountService);
        }
        ```
    - 객체는 UserDetails 타입
    
- GrantAuthority
    - “ROLE_USER”, “ROLE_ADMIN”등 Principal이 가지고 있는 **권한**을 나타낸다.
    - 인증 이후, 인가 및 권한 확인할 때 이 정보를 참조한다.
    
- UserDetails
    - 애플리케이션이 가지고 있는 유저 정보와 스프링 시큐리티가 사용하는 Authentication 객체 사이의 어댑터.

- UserDetailsService
    - 유저 정보를 UserDetails 타입으로 가져오는 DAO (Data Access Object) 인터페이스.
    - 구현은 마음대로!

    ```
    package net.gentledot.demospringsecurity.account.service;
    
    import net.gentledot.demospringsecurity.account.domain.Account;
    import net.gentledot.demospringsecurity.account.repository.AccountRepository;
    import org.springframework.security.core.userdetails.User;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.stereotype.Service;
    
    @Service
    public class AccountService implements UserDetailsService {
    
        private final AccountRepository accountRepository;
        private final PasswordEncoder passwordEncoder;
    
        public AccountService(AccountRepository accountRepository, PasswordEncoder passwordEncoder) {
            this.accountRepository = accountRepository;
            this.passwordEncoder = passwordEncoder;
        }
    
        // username을 받아 해당하는 user 정보를 가져와 UserDetails로 return
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            Account account = accountRepository.findByUsername(username);
    
            if (username == null) {
                throw new UsernameNotFoundException(username);
            }
    
            return User.builder()
                    .username(account.getUsername())
                    .password(account.getPassword())
                    .roles(account.getRole())
                    .build();
        }

        public Account createUser(Account account) {
            account.encodePassword(passwordEncoder);
            return  accountRepository.save(account);
        }
    }
    ```

#### AuthenticationManager와 Authentication
Authentication authenticate(Authentication authentication) throws AuthenticationException;

- 스프링 시큐리티에서 인증(Authentication)은 AuthenticationManager가 한다.
    - 인자로 받은 Authentication이 유효한 인증인지 확인​하고 ​Authentication 객체를 리턴​한다.
    - 인증을 확인하는 과정에서 비활성 계정, 잘못된 비번, 잠긴 계정 등의 에러를 던질 수 있다.

```
    package org.springframework.security.authentication;
    
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.AuthenticationException;
    
    /**
     * Processes an {@link Authentication} request.
     *
     * @author Ben Alex
     */
    public interface AuthenticationManager {
  
    	/**
    	 * Attempts to authenticate the passed {@link Authentication} object, returning a
    	 * fully populated <code>Authentication</code> object (including granted authorities)
    	 * if successful.
    	 * exceptions:
    	 * <ul>
    	 * <li>A {@link DisabledException} must be thrown if an account is disabled and the
    	 * <code>AuthenticationManager</code> can test for this state.</li>
    	 * <li>A {@link LockedException} must be thrown if an account is locked and the
    	 * <code>AuthenticationManager</code> can test for account locking.</li>
    	 * <li>A {@link BadCredentialsException} must be thrown if incorrect credentials are
    	 * presented. Whilst the above exceptions are optional, an
    	 * <code>AuthenticationManager</code> must <B>always</B> test credentials.</li>
    	 * </ul>
         */
    	Authentication authenticate(Authentication authentication)
    			throws AuthenticationException;
    }
```

- 구현하는 객체
    - ProviderManager
    - 또는 AuthenticationManager 구현
    
```
// ProviderManager.class
for (AuthenticationProvider provider : getProviders()) {
    if (!provider.supports(toTest)) {
        continue;
    }

    if (debug) {
        logger.debug("Authentication attempt using "
                + provider.getClass().getName());
    }

    try {
        result = provider.authenticate(authentication);

        if (result != null) {
            copyDetails(authentication, result);
            break;
        }
    }
    catch (AccountStatusException | InternalAuthenticationServiceException e) {
        prepareException(e, authentication);
        // SEC-546: Avoid polling additional providers if auth failure is due to
        // invalid account status
        throw e;
    } catch (AuthenticationException e) {
        lastException = e;
    }
}
```

- Provider
   -  public abstract class AbstractUserDetailsAuthenticationProvider
        - public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider
            ```
            protected final UserDetails retrieveUser(String username,
                    UsernamePasswordAuthenticationToken authentication)
                    throws AuthenticationException {
                prepareTimingAttackProtection();
                try {
                    UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
                    if (loadedUser == null) {
                        throw new InternalAuthenticationServiceException(
                                "UserDetailsService returned null, which is an interface contract violation");
                    }
                    return loadedUser;
                }
                catch (UsernameNotFoundException ex) {
                    mitigateAgainstTimingAttack(authentication);
                    throw ex;
                }
                catch (InternalAuthenticationServiceException ex) {
                    throw ex;
                }
                catch (Exception ex) {
                    throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
                }
            }
            ```
            - UserDetailService
                - AccountService extend UserDetailService
                
- 인자로 받은 Authentication
    - 사용자가 입력한 인증에 필요한 정보(username, password)로 만든 객체. (폼 인증인 경우)
    - Authentication
        - Principal: “test1”
        - Credentials: “test123”

- 유효한 인증인지 확인
    - 사용자가 입력한 password가 UserDetailsService를 통해 읽어온 UserDetails 객체에 들어있는 password와 일치하는지 확인
    - 해당 사용자 계정이 잠겨 있진 않은지, 비활성 계정은 아닌지 등 확인

- Authentication 객체를 리턴
    - Authentication
        - Principal: UserDetailsService에서 리턴한 객체 (AccountService에서 리턴한 객체인 User)
    - Credentials: Null
    - GrantedAuthorities

#### ThreadLocal
- Java.lang 패키지에서 제공하는 thread 범위 변수. 즉, thread 수준의 데이터 저장소.
    - SecurityContextHolder의 기본 전략.
    - 같은 thread 내에서만 공유.
    - 따라서 같은 thread라면 해당 데이터를 메소드 매개변수로 넘겨줄 필요 없음.

```
public class AccountContext {
    private static final ThreadLocal<Account> ACCOUNT_THREAD_LOCAL = new ThreadLocal<>();

    public static void setAccount(Account account) {
        ACCOUNT_THREAD_LOCAL.set(account);
    }
    public static Account getAccount() {
        return ACCOUNT_THREAD_LOCAL.get();
    }
}
```

- 인증된 SecurityContextHolder (Authentication 객체)는 어떻게 되는가?
    - public class SecurityContextPersistenceFilter extends GenericFilterBean
        - SecurityContext를 HTTP session에 캐시(기본 전략)하여 여러 요청에서 Authentication을 공유하는 필터.
        - SecurityContextRepository를 교체하여 세션을 HTTP session이 아닌 다른 곳에 저장하는 것도 가능하다.
            - public class HttpSessionSecurityContextRepository implements SecurityContextRepository
    
    - public class UsernamePasswordAuthenticationFilter extends
      		AbstractAuthenticationProcessingFilter
        - 폼 인증을 처리하는 시큐리티 필터
        - 인증된 Authentication 객체를 SecurityContextHolder에 넣어주는 필터
        - SecurityContextHolder.getContext().setAuthentication(authentication)


#### Spring Security Filter와 FilterChainProxy
- 스프링 시큐리티가 제공하는 필터들
1. WebAsyncManagerIntergrationFilter
1. **SecurityContextPersistenceFilter**
1. HeaderWriterFilter
1. CsrfFilter
1. LogoutFilter
1. **UsernamePasswordAuthenticationFilter**
1. DefaultLoginPageGeneratingFilter
1. DefaultLogoutPageGeneratingFilter
1. BasicAuthenticationFilter
1. RequestCacheAwareFtiler
1. SecurityContextHolderAwareReqeustFilter
1. AnonymouseAuthenticationFilter
1. SessionManagementFilter
1. ExeptionTranslationFilter
1. FilterSecurityInterceptor


- public class FilterChainProxy extends GenericFilterBean
    - filter 목록 가져오기
        ```
        private List<Filter> getFilters(HttpServletRequest request) {
            for (SecurityFilterChain chain : filterChains) {
                if (chain.matches(request)) {
                    return chain.getFilters();
                }
            }
            return null;
        }
        ```
    
    - filter 목록의 구성은 public class SecurityConfig extends WebSecurityConfigurerAdapter
        1. WebSecurityConfigurerAdapter 상속 객체가 여럿일 때 @Order
        1. http.antMatcher()

*** [Difference between antMatcher and mvcMatcher](https://stackoverflow.com/questions/50536292/difference-between-antmatcher-and-mvcmatcher)
> Generally mvcMatcher is more secure than an antMatcher. As an example:
> - antMatchers("/secured") matches only the exact /secured URL
> - mvcMatchers("/secured") matches /secured as well as /secured/, /secured.html, /secured.xyz

- DelegatingFilterProxy
    - 일반적인 servlet 필터
    - servlet 필터 처리를 스프링에 들어있는 빈으로 위임하고 싶을 때 사용하는 servlet 필터.
    - 타겟 빈 이름을 설정한다.
    - 스프링 부트 없이 스프링 시큐리티 설정할 때는 AbstractSecurityWebApplicationInitializer를 사용해서 등록.
    - 스프링 부트를 사용할 때는 자동으로 등록 된다. (SecurityFilterAutoConfiguration)
        - public abstract class AbstractSecurityWebApplicationInitializer
		implements WebApplicationInitializer
		    - public static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain"
		    

#### AccessControl(Authorization)
- AccessDecisionManager 
    - Access Control 결정(인가)을 내리는 인터페이스로, 구현체 3가지를 기본으로 제공한다.
        - AffirmativeBased​: 여러 Voter중에 한명이라도 허용하면 허용. 기본 전략.
        - ConsensusBased: 다수결
        - UnanimousBased: 만장일치
        
    - public class AffirmativeBased extends AbstractAccessDecisionManager

- AccessDecisionVoter
    - 해당 Authentication이 특정한 Object에 접근할 때 필요한 ConfigAttributes를 만족하는지 확인한다.
    - WebExpressionVoter​: 웹 시큐리티에서 사용하는 기본 구현체, ROLE_Xxxx가 매치하는지 확인.
    - RoleHierarchyVoter: 계층형 ROLE 지원. ADMIN > MANAGER > USER
    - getDecisionVoters()

        ```
        public void decide(Authentication authentication, Object object,
                    Collection<ConfigAttribute> configAttributes) throws AccessDeniedException {
            int deny = 0;
        
            for (AccessDecisionVoter voter : getDecisionVoters()) {
                int result = voter.vote(authentication, object, configAttributes);
        
                if (logger.isDebugEnabled()) {
                    logger.debug("Voter: " + voter + ", returned: " + result);
                }
        
                switch (result) {
                case AccessDecisionVoter.ACCESS_GRANTED:
                    return;
        
                case AccessDecisionVoter.ACCESS_DENIED:
                    deny++;
        
                    break;
        
                default:
                    break;
                }
            }
        }
        ```

- AccessDecisionVoter를 커스터마이징 하는 방법
    - 계층형 ROLE 설정
    
    ```
    package net.gentledot.demospringsecurity.config;
    
    import net.gentledot.demospringsecurity.account.service.AccountService;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.access.expression.SecurityExpressionHandler;
    import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
    import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
    //                .accessDecisionManager(accessDecisionManager());
                    .expressionHandler(expressionHandler());
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
    ```
    
#### FilterSecurityInterceptor
AccessDecisionManager를 사용하여 Access Control 또는 예외 처리 하는 필터.
대부분의 경우 FilterChainProxy에 제일 마지막 필터로 들어있다.

public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements
		Filter
		
```
// public abstract class AbstractSecurityInterceptor implements InitializingBean,
   		ApplicationEventPublisherAware, MessageSourceAware

// Attempt authorization
try {
    this.accessDecisionManager.decide(authenticated, object, attributes);
}
catch (AccessDeniedException accessDeniedException) {
    publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated,
            accessDeniedException));

    throw accessDeniedException;
}
```

- ExceptionTranslationFilter
    - 필터 체인에서 발생하는 AccessDeniedException과 AuthenticationException을 처리하는 필터
    
    - AuthenticationException 발생 시 (권한이 요구되는 페이지에 권한없이 접근할 때)
        - AuthenticationEntryPoint 실행
        - AbstractSecurityInterceptor 하위 클래스(예, FilterSecurityInterceptor)에서 발생하는 예외만 처리.
            
    - AccessDeniedException 발생 시 (권한이 요구되는 페이지에 요구되는 권한이 아닌걸 가지고 요청할 때)
        - 익명 사용자라면 AuthenticationEntryPoint 실행
        - 익명 사용자가 아니면 AccessDeniedHandler에게 위임

    - 그렇다면 UsernamePasswordAuthenticationFilter에서 발생한 인증 에러는?
        - public class UsernamePasswordAuthenticationFilter extends
          		AbstractAuthenticationProcessingFilter
            - AbstractAuthenticationProcessingFilter.unsuccessfulAuthentication(request, response, failed);
                ```
                Authentication authResult;
                
                try {
                    authResult = attemptAuthentication(request, response);
                    if (authResult == null) {
                        // return immediately as subclass has indicated that it hasn't completed
                        // authentication
                        return;
                    }
                    sessionStrategy.onAuthentication(authResult, request, response);
                }
                catch (InternalAuthenticationServiceException failed) {
                    logger.error(
                            "An internal error occurred while trying to authenticate the user.",
                            failed);
                    unsuccessfulAuthentication(request, response, failed);
        
                    return;
                }
                catch (AuthenticationException failed) {
                    // Authentication failed
                    unsuccessfulAuthentication(request, response, failed);
        
                    return;
                }
                ```
                
                - SimpleUrlAuthenticationFailureHandler.saveException(request, exception)
                ```
                // public class SimpleUrlAuthenticationFailureHandler implements
                		AuthenticationFailureHandler
                public void onAuthenticationFailure(HttpServletRequest request,
                			HttpServletResponse response, AuthenticationException exception)
                			throws IOException, ServletException {
                
                    if (defaultFailureUrl == null) {
                        logger.debug("No failure URL set, sending 401 Unauthorized error");
            
                        response.sendError(HttpStatus.UNAUTHORIZED.value(),
                            HttpStatus.UNAUTHORIZED.getReasonPhrase());
                    }
                    else {
                        saveException(request, exception);
            
                        if (forwardToDestination) {
                            logger.debug("Forwarding to " + defaultFailureUrl);
            
                            request.getRequestDispatcher(defaultFailureUrl)
                                    .forward(request, response);
                        }
                        else {
                            logger.debug("Redirecting to " + defaultFailureUrl);
                            redirectStrategy.sendRedirect(request, response, defaultFailureUrl);
                        }
                    }
                }
              
                protected final void saveException(HttpServletRequest request,
                			AuthenticationException exception) {
                    if (forwardToDestination) {
                        request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
                    }
                    else {
                        HttpSession session = request.getSession(false);
            
                        if (session != null || allowSessionCreation) {
                            request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION,
                                    exception);
                        }
                    }
                }
                ```

#### Architecture 정리
- Security Filter
    - public final class WebSecurity extends
    		AbstractConfiguredSecurityBuilder<Filter, WebSecurity> implements
    		SecurityBuilder<Filter>, ApplicationContextAware
    ```
    /**
     * <p>
     * The {@link WebSecurity} is created by {@link WebSecurityConfiguration} to create the
     * {@link FilterChainProxy} known as the Spring Security Filter Chain
     * (springSecurityFilterChain). The springSecurityFilterChain is the {@link Filter} that
     * the {@link DelegatingFilterProxy} delegates to.
     * </p>
     *
     * <p>
     * Customizations to the {@link WebSecurity} can be made by creating a
     * {@link WebSecurityConfigurer} or more likely by overriding
     * {@link WebSecurityConfigurerAdapter}.
     * </p>
     *
     * @see EnableWebSecurity
     * @see WebSecurityConfiguration
     *
     * @author Rob Winch
     * @since 3.2
     */    
    ```
  
- 인증 (AuthenticationManager)
    - SecurityContextPersistenceFilter
        - AuthenticationManager
            - ProviderManager
                - DaoAuthenticationProvider
                    - UserDetailService

- 인가(AccessDecisionManager)
    - FilterSecurityInterceptor
        - AccessDecisionManager
            - AffirmativeBased
                - WebExpressionVoter(AccessDecisionVoters)
                    - SecurityExpressionHandler


### Web Application Security

#### ignoring
WebSecurity의 ignoring()을 사용해서 시큐리티 필터 적용을 제외할 요청을 설정할 수 있다.

```
@Override
public void configure(WebSecurity web) throws Exception {
//        web.ignoring().mvcMatchers("/favicon.ico");
    web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
}
```

- web.ignoring()
    - .requestMatchers()
    
        [requestMatchers](https://docs.spring.io/spring-security/site/docs/4.2.13.RELEASE/apidocs/org/springframework/security/config/annotation/web/builders/HttpSecurity.html#requestMatchers--)
        >public HttpSecurity.RequestMatcherConfigurer requestMatchers()
        Allows specifying which HttpServletRequest instances this HttpSecurity will be invoked on. This method allows for easily invoking the HttpSecurity for multiple different RequestMatcher instances. If only a single RequestMatcher is necessary consider using mvcMatcher(String), antMatcher(String), regexMatcher(String), or requestMatcher(RequestMatcher).
        Invoking requestMatchers() will not override previous invocations of mvcMatcher(String)}, requestMatchers(), antMatcher(String), regexMatcher(String), and requestMatcher(RequestMatcher).
    - .requestMatcher(RequestMatcher matcher)
    - .mvcMatchers(String mvcPatterns)
    - .antMatchers(String antPatterns)
    - .regexMatchers(String regexPatterns)

- PathRequest
    - org.springframework.boot.autoconfigure.security.servlet.PathRequest
    - Spring Boot가 제공하는 PathRequest를 사용해서 정적 지원 요청을 필터를 적용하지 않도록 설정.
 

- http.authorizeRequests()
.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
    - 위의 web.ignoring()와 같은 결과가 나오지만...
    - security filter가 적용된다는 차이가 있음.

- 정적 / 동적 resource에 따른 처리방식.
    - 동적 resource는 http.authorizeRequests()로 처리하는 것을 권장.
    - 정적 resource는 WebSecurity.ignore()를 권장하며 예외적인 정적 자원 (인증이 필요한
      정적자원이 있는 경우)는 http.authorizeRequests()를 사용할 수 있습니다.
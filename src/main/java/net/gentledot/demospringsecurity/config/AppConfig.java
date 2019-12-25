package net.gentledot.demospringsecurity.config;

import net.gentledot.demospringsecurity.account.domain.Account;
import net.gentledot.demospringsecurity.account.domain.Book;
import net.gentledot.demospringsecurity.account.repository.BookRepository;
import net.gentledot.demospringsecurity.account.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
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
        // 비밀번호가 평문 그대로 저장 (비추천!)
//        return NoOpPasswordEncoder.getInstance();
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public ApplicationRunner applicationRunner(){

        return new ApplicationRunner() {
            @Autowired
            AccountService accountService;

            @Autowired
            BookRepository bookRepository;

            @Override
            public void run(ApplicationArguments args) throws Exception {
            // test - howToTest
            // orm - hibernate
            String role = "USER";
            Account test = createUser("test", "test", role);
            Account orm= createUser("orm", "qwer1234", role);

            accountService.createUser(test);
            accountService.createUser(orm);

            Book howToTest = createBook("howToTest", test);
            Book hibernate =  createBook("hibernate", orm);

            bookRepository.save(howToTest);
            bookRepository.save(hibernate);
            }
        };
    }

    private Book createBook(String title, Account account) {

        return Book.builder()
                .title(title)
                .author(account)
                .build();
    }

    private Account createUser(String username, String password, String roleStr) {

        return Account.builder()
                .username(username)
                .password(password)
                .role(roleStr)
                .build();
    }

}

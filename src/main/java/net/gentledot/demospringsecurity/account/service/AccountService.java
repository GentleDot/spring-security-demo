package net.gentledot.demospringsecurity.account.service;

import net.gentledot.demospringsecurity.account.domain.Account;
import net.gentledot.demospringsecurity.account.domain.UserAccount;
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

        // username == null 에서 변경
        // 로그인하지 않았지만 rememberMe Token 에 있는 userName으로 조회할 수도 있기 때문에 변경 필요.
        if (account == null) {
            throw new UsernameNotFoundException(username);
        }

        /*return User.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();*/

        return new UserAccount(account);
    }

    public Account createUser(Account account) {
        account.encodePassword(passwordEncoder);
        return  accountRepository.save(account);
    }
}

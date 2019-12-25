package net.gentledot.demospringsecurity.account.service;

import net.gentledot.demospringsecurity.common.SecurityLogger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

    private Logger logger = LogManager.getLogger(this.getClass());

    @Secured("ROLE_USER")
    public void dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Object credentials = authentication.getCredentials();
        boolean authenticated = authentication.isAuthenticated();

        logger.debug("======SecurityContextHolder======");
        logger.debug("authentication : " + authentication);
        logger.debug("principal : " + principal);
        logger.debug("username : " + principal.getUsername());
        logger.debug("credentials : " + credentials);
        logger.debug("authenticated : " + authenticated);
        logger.debug("======SecurityContextHolder======");

    }

    @Async
    public void asyncService() {
        SecurityLogger.log("in the async service.");
        System.out.println("Async Service is called.");
    }
}

package net.gentledot.demospringsecurity.common;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
public class AccessDeniedLogger {

    public Log logger = LogFactory.getLog(AccessDeniedLogger.class);

    public AccessDeniedHandler deniedHandle() {
        return (request, response, accessDeniedException) -> {
            UserDetails principal = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String username = principal.getUsername();
            logger.debug("===AccessDeniedLogger===");
            logger.debug("user_" + username + " is denied to access " + request.getRequestURI());
            logger.debug("===AccessDeniedLogger===");
            response.sendRedirect("/access-denied");
        };
    }
}

package com.otilm.core.config;

import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

public class CustomAuditAware implements AuditorAware<String> {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuditAware.class);

    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            // Normal for system-originated work, but also what a lost identity looks like. Debug rather than warn:
            // unauthenticated audited writes are frequent, so a warning here would be noise.
            logger
                    .debug("No authentication in context while resolving auditor; audited records will be attributed to the system user.");
            return Optional.of("system");
        }

        if (authentication.getPrincipal() instanceof User) {
            String username = ((User) authentication.getPrincipal()).getUsername();
            return Optional.of(username);
        } else if (authentication.getPrincipal() instanceof String
                && "anonymousUser".equals(authentication.getPrincipal())) {
            // for connector self registration
            return Optional.of("anonymousUser");
        } else {
            throw new IllegalStateException("Unexpected type of principal.");
        }
    }
}

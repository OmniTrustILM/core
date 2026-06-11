package com.otilm.core.config;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import java.util.Optional;

public class CustomAuditAware implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null)
            return Optional.of("system");

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

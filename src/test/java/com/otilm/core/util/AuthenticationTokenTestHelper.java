package com.otilm.core.util;

import java.util.List;
import java.util.UUID;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class AuthenticationTokenTestHelper {

    public static AnonymousAuthenticationToken getAnonymousToken(String username) {
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ANONYMOUS"));
        return new AnonymousAuthenticationToken(UUID.randomUUID().toString(), new User(username, "", authorities),
                authorities);
    }
}

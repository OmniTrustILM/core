package com.czertainly.core.security.authn.client;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

@Getter
public class AuthenticationInfo {

    private static final String ANONYMOUS_USERNAME = "anonymousUser";

    private final AuthMethod authMethod;
    private final String userUuid;
    private final String username;
    private final List<GrantedAuthority> authorities;
    private final String rawData;

    public boolean isAnonymous() {
        return this.username.equals(ANONYMOUS_USERNAME);
    }

    public AuthenticationInfo(AuthMethod authMethod, String userUuid, String username, List<GrantedAuthority> authorities, String rawData) {
        this.authMethod = authMethod;
        this.userUuid = userUuid;
        this.username = username;
        this.authorities = authorities;
        this.rawData = rawData;
    }

    public AuthenticationInfo(AuthMethod authMethod, String userUuid, String username, List<GrantedAuthority> authorities) {
        this.authMethod = authMethod;
        this.userUuid = userUuid;
        this.username = username;
        this.authorities = authorities;
        List<String> roles = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        this.rawData = "{" +
                " \"user\": {\"username\":\"" + this.username + "\"}," +
                " \"roles\": [" + roles.stream().map(a -> "\"" + a +"\"").collect(Collectors.joining(",")) + "]" +
                "}";
    }

    public static AuthenticationInfo getAnonymousAuthenticationInfo() {
        return new AuthenticationInfo(AuthMethod.NONE, null, ANONYMOUS_USERNAME, List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
    }
}

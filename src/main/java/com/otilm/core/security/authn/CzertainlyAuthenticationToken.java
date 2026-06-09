package com.otilm.core.security.authn;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CzertainlyAuthenticationToken extends AbstractAuthenticationToken {


    private final CzertainlyUserDetails principal;

    private final String credentials;

    private boolean isAuthenticated;

    public CzertainlyAuthenticationToken(CzertainlyUserDetails principal) {
        this(principal, "", principal.getAuthorities(), true);
    }

    protected CzertainlyAuthenticationToken(
            CzertainlyUserDetails principal,
            String credentials,
            Collection<? extends GrantedAuthority> authorities,
            Boolean isAuthenticated
    ) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public CzertainlyUserDetails getPrincipal() {
        return this.principal;
    }

    @Override
    public boolean isAuthenticated() {
        return this.isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) throw new IllegalArgumentException("Once created, CzertainlyAuthenticationToken.isAuthenticated can't be set to true.");
        this.isAuthenticated = false;
    }

    @Override
    public String getName() {
        return this.principal.getUserUuid();
    }
}

package com.otilm.core.security.authn;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
public class CzertainlyAnonymousToken extends AnonymousAuthenticationToken {


    private boolean accessingPermitAllEndpoint = false;

    /**
     * Constructor.
     *
     * @param key         to identify if this object made by an authorised client
     * @param principal   the principal (typically a <code>UserDetails</code>)
     * @param authorities the authorities granted to the principal
     * @throws IllegalArgumentException if a <code>null</code> was passed
     */
    public CzertainlyAnonymousToken(String key, Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(key, principal, authorities);
    }



}

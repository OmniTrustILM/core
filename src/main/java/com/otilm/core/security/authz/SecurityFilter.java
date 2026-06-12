package com.otilm.core.security.authz;

import lombok.Data;

@Data
public class SecurityFilter {
    private SecurityResourceFilter resourceFilter;

    private SecurityResourceFilter parentResourceFilter;

    private SecurityResourceFilter groupMembersFilter;

    private String parentRefProperty;

    public static SecurityFilter create() {
        return new SecurityFilter();
    }

}

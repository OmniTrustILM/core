package com.czertainly.core.security.authn;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;

@Getter
public class CzertainlyUserDetails extends User implements Serializable {

    private final String rawData;
    private final String userUuid;
    private final AuthMethod authMethod;

    public CzertainlyUserDetails(AuthenticationInfo authInfo) {
        super(authInfo.getUsername(), "", authInfo.getAuthorities());
        this.rawData = authInfo.getRawData();
        this.userUuid = authInfo.getUserUuid();
        this.authMethod = authInfo.getAuthMethod();
    }
}

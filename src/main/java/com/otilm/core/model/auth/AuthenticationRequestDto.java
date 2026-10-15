package com.otilm.core.model.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@Setter
@Getter
public class AuthenticationRequestDto {

    @JsonIgnore
    private AuthMethod authMethod;

    @Schema(description = "Base64 Content of the certificate")
    private String certificateContent;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @Schema(description = "Untrusted intermediate certificates as canonical Base64 DER")
    private List<String> certificateChain;

    @Schema(description = "Authentication Token User Claims")
    private Map<String, Object> authenticationTokenUserClaims;

    @Schema(description = "System Username")
    private String systemUsername;

    @Schema(description = "User UUID")
    private String userUuid;

    @JsonIgnore
    public String getAuthData(boolean withLabel) {
        return withLabel ? switch (authMethod) {
            case NONE -> "";
            case CERTIFICATE -> "Certificate: " + certificateContent;
            case TOKEN, SESSION -> "Token: " + StringUtils.join(authenticationTokenUserClaims);
            case API_KEY -> "";
            case USER_PROXY -> systemUsername != null ? "System username: " + systemUsername : "User UUID: " + userUuid;
        } : switch (authMethod) {
            case NONE -> null;
            case CERTIFICATE -> certificateContent;
            case TOKEN, SESSION -> StringUtils.join(authenticationTokenUserClaims);
            case API_KEY -> null;
            case USER_PROXY -> systemUsername != null ? systemUsername : userUuid;
        };
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("certificateContent", certificateContent)
                .append("authenticationTokenUserClaims", StringUtils.join(authenticationTokenUserClaims))
                .append("systemUsername", systemUsername)
                .append("userUuid", userUuid)
                .toString();
    }
}

package com.otilm.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ETag;

/**
 * Strong entity tag of a stored OAuth2 provider. The tag is derived from the stored settings without the client secret,
 * so it reveals nothing about the secret and does not change when only the secret changes.
 */
final class OAuth2ProviderSettingsEntityTag {

    private static final ObjectMapper STORAGE_MAPPER = ObjectMapperFactory.storage();

    private OAuth2ProviderSettingsEntityTag() {
    }

    /**
     * The settings are read into their stored type and written again before hashing, so a row written by an older
     * version, which lacks fields added since, has the same tag as the row an update rewrites from it.
     *
     * @param storedValue the provider's stored settings as JSON
     * @return the quoted, base64url encoded SHA-256 of the settings without the client secret
     * @throws JsonProcessingException when the stored value is not valid JSON
     */
    static String of(String storedValue) throws JsonProcessingException {
        OAuth2ProviderSettingsDto settings = STORAGE_MAPPER.readValue(storedValue, OAuth2ProviderSettingsDto.class);
        settings.setClientSecret(null);
        byte[] serialized = STORAGE_MAPPER.writeValueAsBytes(settings);
        byte[] digest = sha256(serialized);
        return "\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest) + "\"";
    }

    /**
     * A blank header is no precondition. Otherwise any wildcard matches and a tag matches only when it is strong and
     * equal to the current one.
     */
    static boolean matches(String ifMatch, String currentTag) {
        if (StringUtils.isBlank(ifMatch)) {
            return true;
        }
        for (ETag candidate : ETag.parse(ifMatch)) {
            if (candidate.isWildcard()) {
                return true;
            }
            if (!candidate.weak() && currentTag.equals(candidate.formattedTag())) {
                return true;
            }
        }
        return false;
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}

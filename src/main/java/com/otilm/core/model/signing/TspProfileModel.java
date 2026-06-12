package com.otilm.core.model.signing;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;

import java.util.List;
import java.util.UUID;

/**
 * Model layer representation of a TSP Profile used on the TSP timestamping hot path.
 *
 * @param uuid                           UUID of the TSP Profile.
 * @param name                           Name of the TSP Profile.
 * @param description                    Optional description.
 * @param enabled                        Whether the profile is currently enabled.
 * @param defaultSigningProfileUuid      UUID of the default Signing Profile, or {@code null} if not set.
 * @param defaultSigningProfileName      Name of the default Signing Profile, or {@code null} if not set.
 * @param customAttributes               Custom attributes attached to this profile.
 * @param allowedAuthenticationMethods   Authentication methods this profile accepts.
 * @param basicCredentials               Read-only credential references for BASIC_PASSWORD authentication; never carries secret values, but carries the stored verification fingerprint of the latest secret version.
 * @param vaultProfileUuid               Vault profile that stores this profile's Basic credentials, or {@code null} if none configured.
 */
public record TspProfileModel(
        UUID uuid,
        String name,
        String description,
        boolean enabled,
        UUID defaultSigningProfileUuid,
        String defaultSigningProfileName,
        List<ResponseAttribute> customAttributes,
        List<TspAuthenticationMethod> allowedAuthenticationMethods,
        List<BasicCredentialRef> basicCredentials,
        UUID vaultProfileUuid
) {
    public record BasicCredentialRef(String username, UUID secretUuid, UUID mappedUserUuid, String fingerprint) {}
}

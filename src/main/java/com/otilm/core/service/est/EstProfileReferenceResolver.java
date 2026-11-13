package com.otilm.core.service.est;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.est.BaseEstProfileRequestDto;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.RaProfileInternalService;
import com.otilm.core.service.TokenProfileInternalService;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.util.CertificateUtil;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Resolves what an EST Profile request refers to, before anything is written. Every reference is read through the
 * DETAIL-authorized loader of the referenced resource, so a profile can only point at objects its author may see, and
 * secrets made credentials through the gate a read of their content passes. The connector is called last, once
 * everything local has been accepted.
 */
@Component
public class EstProfileReferenceResolver {

    private final AttributeEngine attributeEngine;
    private final AuthorizationEnforcer authorizationEnforcer;
    private final RaProfileInternalService raProfileService;
    private final RaProfileRepository raProfileRepository;
    private final SecretRepository secretRepository;
    private final CertificateInternalService certificateService;
    private final TokenProfileInternalService tokenProfileService;
    private final ExtendedAttributeService extendedAttributeService;
    private final EstKeyRecoveryTokenProfileCheck keyRecoveryCheck;

    // S107: one collaborator per kind of reference the resolver checks.
    @SuppressWarnings("java:S107")
    public EstProfileReferenceResolver(AttributeEngine attributeEngine, AuthorizationEnforcer authorizationEnforcer,
            RaProfileInternalService raProfileService, RaProfileRepository raProfileRepository,
            SecretRepository secretRepository, CertificateInternalService certificateService,
            TokenProfileInternalService tokenProfileService, ExtendedAttributeService extendedAttributeService,
            EstKeyRecoveryTokenProfileCheck keyRecoveryCheck) {
        this.attributeEngine = attributeEngine;
        this.authorizationEnforcer = authorizationEnforcer;
        this.raProfileService = raProfileService;
        this.raProfileRepository = raProfileRepository;
        this.secretRepository = secretRepository;
        this.certificateService = certificateService;
        this.tokenProfileService = tokenProfileService;
        this.extendedAttributeService = extendedAttributeService;
        this.keyRecoveryCheck = keyRecoveryCheck;
    }

    /**
     * @param acceptedSecretUuids the secrets the stored profile already accepts as credentials, none for a new profile
     */
    public References resolve(BaseEstProfileRequestDto request, Collection<UUID> acceptedSecretUuids)
            throws ConnectorException, AttributeException, NotFoundException {
        attributeEngine.validateCustomAttributesContent(Resource.EST_PROFILE, request.getCustomAttributes());
        RaProfile raProfile = resolveRaProfile(request.getRaProfileUuid());
        List<UUID> secretUuids = distinct(request.getBasicCredentialSecretUuids());
        List<UUID> keptSecretUuids = secretUuids.stream().filter(acceptedSecretUuids::contains).toList();
        checkBasicCredentialSecrets(secretUuids, keptSecretUuids);
        List<UUID> certificateUuids = resolveTrustedCaCertificates(request.getTrustedCaCertificateUuids());
        TokenProfile tokenProfile = resolveKeyRecoveryTokenProfile(request.getKeyRecoveryTokenProfileUuid());
        validateIssueAttributes(raProfile, request.getIssueCertificateAttributes());
        if (request.isKeyRecovery()) {
            keyRecoveryCheck.check(tokenProfile, request.getKeyRecoveryKeyAttributes());
        }
        return new References(raProfile, secretUuids, keptSecretUuids, certificateUuids, tokenProfile);
    }

    /**
     * The connector that checks and keys the issue attributes of the RA Profile, or null when its authority has none.
     */
    public static UUID issueConnectorUuid(RaProfile raProfile) {
        if (raProfile == null || raProfile.getAuthorityInstanceReference() == null) {
            return null;
        }
        return raProfile.getAuthorityInstanceReference().getConnectorUuid();
    }

    /**
     * The authorized load decides whether the caller may use the RA Profile; the second read fetches its authority and
     * connector, which the connector call made outside any transaction cannot load lazily.
     */
    public RaProfile resolveRaProfile(UUID raProfileUuid) throws NotFoundException {
        if (raProfileUuid == null) {
            return null;
        }
        raProfileService.getRaProfileEntity(SecuredUUID.fromUUID(raProfileUuid));
        return raProfileRepository
                .findWithAuthorityByUuid(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
    }

    /**
     * A secret made an RA credential lets whoever knows its content enroll, so the operator putting it in charge must
     * be able to read that content. That takes both permissions a read of it is gated on: the content permission on the
     * secret, and membership of the vault profile it is sourced from. A secret the profile already accepts was put in
     * charge before and is kept without them: an edit replaces every setting, so gating it would lock an operator who
     * cannot read it out of all the others.
     */
    private void checkBasicCredentialSecrets(List<UUID> secretUuids, List<UUID> keptSecretUuids)
            throws NotFoundException {
        if (secretUuids.isEmpty()) {
            return;
        }
        List<UUID> addedSecretUuids = secretUuids.stream().filter(uuid -> !keptSecretUuids.contains(uuid)).toList();
        if (!addedSecretUuids.isEmpty()) {
            // Before the lookup, so a caller who may not read secrets learns nothing about which UUIDs exist.
            authorizationEnforcer
                    .enforce(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT,
                            addedSecretUuids.stream().map(SecuredUUID::fromUUID).toList());
        }
        List<Secret> secrets = findSecrets(secretUuids);
        List<Secret> addedSecrets = secrets
                .stream()
                .filter(secret -> addedSecretUuids.contains(secret.getUuid()))
                .toList();
        if (!addedSecrets.isEmpty()) {
            authorizationEnforcer
                    .enforce(Resource.VAULT_PROFILE, ResourceAction.MEMBERS, sourceVaultProfiles(addedSecrets));
        }
        for (Secret secret : secrets) {
            if (secret.getType() != SecretType.BASIC_AUTH) {
                throw new ValidationException("Secret " + secret.getName() + " is not a basic authentication secret");
            }
            if (!secret.isEnabled()) {
                throw new ValidationException("Secret " + secret.getName() + " is disabled");
            }
        }
    }

    private List<Secret> findSecrets(List<UUID> secretUuids) throws NotFoundException {
        List<Secret> secrets = secretRepository.findByUuidIn(secretUuids);
        Set<UUID> found = secrets.stream().map(Secret::getUuid).collect(Collectors.toSet());
        for (UUID secretUuid : secretUuids) {
            if (!found.contains(secretUuid)) {
                throw new NotFoundException(Secret.class, secretUuid);
            }
        }
        return secrets;
    }

    private static List<SecuredUUID> sourceVaultProfiles(List<Secret> secrets) {
        return secrets
                .stream()
                .map(Secret::getSourceVaultProfileUuid)
                .filter(Objects::nonNull)
                .distinct()
                .map(SecuredUUID::fromUUID)
                .toList();
    }

    private List<UUID> resolveTrustedCaCertificates(List<UUID> requested) throws NotFoundException {
        List<UUID> certificateUuids = distinct(requested);
        for (UUID certificateUuid : certificateUuids) {
            Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromUUID(certificateUuid));
            CertificateSubjectType subjectType = certificate.getSubjectType();
            if (subjectType == null || !subjectType.isCa()) {
                throw new ValidationException("Certificate "
                        + CertificateUtil.formatCommonName(certificate.getCommonName()) + " is not a CA certificate");
            }
        }
        return certificateUuids;
    }

    /** The authorized lookup returns only the name, so the enabled flag comes from the entity read after it. */
    private TokenProfile resolveKeyRecoveryTokenProfile(UUID tokenProfileUuid) throws NotFoundException {
        if (tokenProfileUuid == null) {
            return null;
        }
        SecuredUUID securedUuid = SecuredUUID.fromUUID(tokenProfileUuid);
        tokenProfileService.getResourceObjectExternal(securedUuid);
        TokenProfile tokenProfile = tokenProfileService.getTokenProfileEntity(securedUuid);
        if (!Boolean.TRUE.equals(tokenProfile.getEnabled())) {
            throw new ValidationException("Key recovery token profile " + tokenProfile.getName() + " is disabled");
        }
        return tokenProfile;
    }

    /**
     * Without a connector on the RA Profile's authority there is nothing to check issue attributes against, so such an
     * RA Profile can be the default only without them.
     */
    private void validateIssueAttributes(RaProfile raProfile, List<RequestAttribute> issueAttributes)
            throws ConnectorException, AttributeException, NotFoundException {
        if (issueConnectorUuid(raProfile) != null) {
            extendedAttributeService.mergeAndValidateIssueAttributes(raProfile, issueAttributes);
        } else if (issueAttributes != null && !issueAttributes.isEmpty()) {
            throw new ValidationException(
                    "Issue certificate attributes need an RA Profile whose authority has a connector");
        }
    }

    private static List<UUID> distinct(List<UUID> uuids) {
        return uuids == null ? new ArrayList<>() : new ArrayList<>(uuids.stream().distinct().toList());
    }

    /**
     * The objects a request refers to, each checked and loaded, with the reference lists free of duplicates. The kept
     * secrets are those the stored profile already accepted, let through without the content gate.
     */
    public record References(RaProfile raProfile, List<UUID> basicCredentialSecretUuids, List<UUID> keptSecretUuids,
            List<UUID> trustedCaCertificateUuids, TokenProfile keyRecoveryTokenProfile) {
    }
}

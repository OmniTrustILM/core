package com.otilm.core.service.est.enrollment;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.attribute.SignatureAlgorithmMapping;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.Pkcs8Envelopes;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.service.est.EstKeyRecoveryKeyAttributes;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstServerKeyGenerationRequest.Content;
import com.otilm.core.util.CertificateRequestUtils;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.springframework.stereotype.Component;

/**
 * The token side of a key generation with key recovery: creates an exportable key on the key-recovery token profile of
 * the EST Profile, has it sign the request, exports it once under a transport passphrase, and destroys a key that the
 * authority will not certify. Each step goes through the platform's own services, authorized for the user the request
 * runs as. The key material lives only in the memory of the request.
 */
@Slf4j
@Component
class EstKeyRecovery {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final CryptographicKeyExternalService keyService;
    private final CryptographicKeyExportExternalService keyExportService;
    private final CryptographicOperationInternalService cryptographicOperationService;
    private final TokenProfileRepository tokenProfileRepository;

    EstKeyRecovery(CryptographicKeyExternalService keyService, CryptographicKeyExportExternalService keyExportService,
            CryptographicOperationInternalService cryptographicOperationService,
            TokenProfileRepository tokenProfileRepository) {
        this.keyService = keyService;
        this.keyExportService = keyExportService;
        this.cryptographicOperationService = cryptographicOperationService;
        this.tokenProfileRepository = tokenProfileRepository;
    }

    /**
     * A key created on a token for one request, named by what the platform keeps of it.
     *
     * @param keyUuid the key
     * @param privateKeyItemUuid the item of its private key, which is exported
     * @param tokenProfileUuid the token profile that the key was created on
     * @param publicKey the public key of the pair
     */
    /** A token key of a type that no signature algorithm of the platform signs with, which no retry changes. */
    static final class NoSignatureAlgorithmException extends IllegalStateException implements PlatformException {

        NoSignatureAlgorithmException(String algorithm) {
            super("The platform signs with no algorithm " + algorithm + " for an EST request");
        }
    }

    record TokenKey(UUID keyUuid, UUID privateKeyItemUuid, UUID tokenProfileUuid, SubjectPublicKeyInfo publicKey) {
    }

    /**
     * Creates an exportable key pair on the key-recovery token profile of the EST Profile, with the create-key
     * attributes that the profile stores and the name {@code est-<label>-<uuid>}. A key whose items cannot be read is
     * destroyed again.
     *
     * @param route the route of the request
     * @return the key
     */
    TokenKey create(EstRoute route)
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        UUID tokenProfileUuid = route.estProfile().getKeyRecoveryTokenProfileUuid();
        UUID tokenUuid = tokenProfileRepository
                .findBasicModelByUuid(tokenProfileUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, tokenProfileUuid))
                .tokenInstanceReferenceUuid();
        KeyDetailDto created = keyService
                .createKey(tokenUuid, SecuredParentUUID.fromUUID(tokenProfileUuid), KeyRequestType.KEY_PAIR,
                        keyRequest(route));
        UUID keyUuid = UUID.fromString(created.getUuid());
        log.debug("Key {} is created on token profile {} for an EST request", keyUuid, tokenProfileUuid);
        try {
            return tokenKeyOf(keyUuid, tokenProfileUuid, created.getItems());
        } catch (RuntimeException e) {
            destroy(null, keyUuid);
            throw e;
        }
    }

    private static KeyRequestDto keyRequest(EstRoute route) {
        KeyRequestDto request = new KeyRequestDto();
        request.setName("est-" + route.realm() + "-" + UUID.randomUUID());
        request.setDescription("Generated for an EST client, kept for key recovery");
        request.setAttributes(EstKeyRecoveryKeyAttributes.of(route.estProfile()));
        request.setCustomAttributes(List.of());
        request.setEnabled(true);
        request.setExportable(true);
        return request;
    }

    private static TokenKey tokenKeyOf(UUID keyUuid, UUID tokenProfileUuid, List<KeyItemDetailDto> items) {
        KeyItemDetailDto privateKey = itemOf(keyUuid, items, KeyType.PRIVATE_KEY);
        KeyItemDetailDto publicKey = itemOf(keyUuid, items, KeyType.PUBLIC_KEY);
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
                .getInstance(Base64.getDecoder().decode(publicKey.getKeyData()));
        return new TokenKey(keyUuid, UUID.fromString(privateKey.getUuid()), tokenProfileUuid, publicKeyInfo);
    }

    private static KeyItemDetailDto itemOf(UUID keyUuid, List<KeyItemDetailDto> items, KeyType type) {
        return items
                .stream()
                .filter(item -> item.getType() == type)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Key " + keyUuid + " created for EST holds no " + type));
    }

    /**
     * Has the key sign a request for the subject and the extensions that the client asked for, with the default
     * signature algorithm of the key's type.
     *
     * @return the signed request
     */
    Pkcs10CertificateRequest signRequest(TokenKey key, Content content) throws NotFoundException,
            GeneralSecurityException, IOException, AttributeException, CertificateRequestException {
        String request = cryptographicOperationService
                .generateCsr(key.keyUuid(), key.tokenProfileUuid(), new X500Principal(content.subject().getEncoded()),
                        content.extensions(), signatureAttributesOf(key.publicKey()), null, null, null);
        return new Pkcs10CertificateRequest(CertificateRequestUtils.normalizeAndDecodeCsr(request));
    }

    /**
     * The attributes that select the default signature algorithm of the key, as a key generated in memory signs.
     *
     * @throws NoSignatureAlgorithmException when the key is of a type that no signature algorithm of the platform signs
     * with
     */
    static List<RequestAttribute> signatureAttributesOf(SubjectPublicKeyInfo publicKey) throws IOException {
        String algorithm = algorithmOf(publicKey);
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm
                .lookupByCode(algorithm)
                .orElseThrow(() -> new NoSignatureAlgorithmException(algorithm));
        log.debug("The token key signs the EST request with {}", signatureAlgorithm.getCode());
        return SignatureAlgorithmMapping.toAttributes(signatureAlgorithm);
    }

    private static String algorithmOf(SubjectPublicKeyInfo publicKey) throws IOException {
        PublicKey key = EstPublicKeys
                .read(publicKey.getEncoded())
                .orElseThrow(() -> new IllegalStateException("The public key of a token key cannot be read"));
        return EstKeyPairGenerator.signatureAlgorithmOf(key);
    }

    /**
     * Exports the private key under a new transport passphrase and opens the export, with the cost limits of an
     * uploaded key file. The passphrase and the exported envelope are overwritten once used.
     *
     * @return the private key, which the caller overwrites once used
     */
    PrivateKeyInfo export(TokenKey key) throws ConnectorException, NotFoundException {
        char[] transport = Pkcs8Envelopes.transportPassphrase(RANDOM);
        Passphrase passphrase = new Passphrase(transport);
        Arrays.fill(transport, '\0');
        byte[] envelope = null;
        try {
            KeyExportRequestDto request = new KeyExportRequestDto();
            request.setPassphrase(passphrase);
            request.setExportAttributes(List.of());
            envelope = keyExportService
                    .exportKey(key.keyUuid(), key.privateKeyItemUuid(), request)
                    .encryptedPrivateKeyInfo();
            return Pkcs8Envelopes.decrypt(envelope, passphrase, DerivationBudget.forFile());
        } finally {
            passphrase.clear();
            if (envelope != null) {
                Arrays.fill(envelope, (byte) 0);
            }
        }
    }

    /**
     * @param privateKey the private key, which stays the caller's
     * @return the public key worked out from the private key, or empty when it cannot be
     */
    Optional<PublicKey> publicKeyOf(PrivateKeyInfo privateKey) {
        try {
            return Pkcs8Envelopes.publicKeyOf(privateKey);
        } catch (ValidationException e) {
            log.debug("The public key of an exported token key cannot be worked out");
            return Optional.empty();
        }
    }

    /**
     * Destroys the key of a request that the authority will not certify. A failure is logged and left, as the request
     * is refused either way.
     *
     * @param certificateUuid the certificate that was requested for the key, {@code null} when none was
     */
    void destroy(UUID certificateUuid, TokenKey key) {
        destroy(certificateUuid, key.keyUuid());
    }

    private void destroy(UUID certificateUuid, UUID keyUuid) {
        log.warn("Key {} created for certificate {} requested through EST is destroyed", keyUuid, certificateUuid);
        try {
            keyService.destroyKey(List.of(keyUuid.toString()));
        } catch (Exception e) {
            log
                    .error("Key {} created for certificate {} requested through EST could not be destroyed: {}",
                            keyUuid, certificateUuid, e.getClass().getName());
        }
    }
}

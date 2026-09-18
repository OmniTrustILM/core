package com.otilm.core.helpers;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.helpers.SigningAlgorithmSpecs.AlgorithmSpec;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import java.security.KeyPair;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;

import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;

public final class TsaSigningMaterial {

    private final CryptographyProviderConnectorMock cryptographyProviderMock;
    private final CryptographicKeyExternalService cryptographicKeyService;
    private final TokenInstanceDetailDto tokenInstance;
    private final TokenProfileDetailDto tokenProfile;
    private final TestCertificateAuthority.TrustedCa trustedCa;
    private final String keyNamePrefix;
    private final String certificateSubjectPrefix;

    private final Map<SignatureAlgorithm, UUID> privateKeyReferenceUuids = new EnumMap<>(SignatureAlgorithm.class);

    public TsaSigningMaterial(CryptographyProviderConnectorMock cryptographyProviderMock,
            CryptographicKeyExternalService cryptographicKeyService, TokenInstanceDetailDto tokenInstance,
            TokenProfileDetailDto tokenProfile, TestCertificateAuthority.TrustedCa trustedCa, String keyNamePrefix,
            String certificateSubjectPrefix) {
        this.cryptographyProviderMock = cryptographyProviderMock;
        this.cryptographicKeyService = cryptographicKeyService;
        this.tokenInstance = tokenInstance;
        this.tokenProfile = tokenProfile;
        this.trustedCa = trustedCa;
        this.keyNamePrefix = keyNamePrefix;
        this.certificateSubjectPrefix = certificateSubjectPrefix;
    }

    /** A timestamping certificate over a fresh key of this algorithm, with the mock wired. */
    public Certificate issueTimestampingCertificate(SignatureAlgorithm signatureAlgorithm) throws Exception {
        AlgorithmSpec spec = SigningAlgorithmSpecs.specFor(signatureAlgorithm);
        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(spec.keyAlgorithm(), spec.keyParameterSpec());

        // The connector reports this UUID as the private key's reference; the same UUID keys the
        // real-signer mock, so runtime sign requests reach this algorithm's live private key.
        UUID privateKeyReferenceUuid = UUID.randomUUID();
        privateKeyReferenceUuids.put(signatureAlgorithm, privateKeyReferenceUuid);
        cryptographyProviderMock
                .stubKeyPairCreation(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                        spec.keyAlgorithm(), privateKeyReferenceUuid)
                .registerSigningKey(privateKeyReferenceUuid, keyPair.getPrivate(), signatureAlgorithm);
        cryptographicKeyService
                .createKey(UUID.fromString(tokenInstance.getUuid()),
                        SecuredParentUUID.fromString(tokenProfile.getUuid()), KeyRequestType.KEY_PAIR,
                        aKeyPairRequest().withName(keyNamePrefix + signatureAlgorithm.getCode().toLowerCase()).build());

        // Uploading the leaf associates it (by public-key fingerprint) with the token-backed key
        return trustedCa.issueTimestampingCertificate(keyPair, certificateSubjectPrefix + signatureAlgorithm.getCode());
    }

    /** The reference the mock signs this algorithm's requests under, so a test can re-register a different key. */
    public UUID privateKeyReferenceUuid(SignatureAlgorithm signatureAlgorithm) {
        return privateKeyReferenceUuids.get(signatureAlgorithm);
    }
}

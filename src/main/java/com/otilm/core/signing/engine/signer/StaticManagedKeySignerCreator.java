package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.CryptographyUtil;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class StaticManagedKeySignerCreator implements SignerCreator {

    private final CryptographicOperationInternalService cryptographicOperationService;

    public StaticManagedKeySignerCreator(CryptographicOperationInternalService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Override
    public boolean supports(ResolvedManagedScheme signingScheme) {
        return signingScheme instanceof ResolvedStaticKeyManagedSigning;
    }

    @Override
    public Signer create(ResolvedManagedScheme signingSchemeModel) throws SigningEngineException {
        ResolvedStaticKeyManagedSigning signingScheme = (ResolvedStaticKeyManagedSigning) signingSchemeModel;

        SigningCertificate certificate = signingScheme.certificate();
        if (certificate.keyUuid() == null) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    String.format("No cryptographic key associated with certificate '%s'", certificate.commonName()),
                    "Signing key could not be found.");
        }

        List<CryptographicKeyItemOperationModel> keyItems = signingScheme.keyItems();

        CryptographicKeyItemOperationModel privateKeyItem = keyItems
                .stream()
                .filter(item -> item.keyType() == KeyType.PRIVATE_KEY)
                .findFirst()
                .orElseThrow(() -> new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                        String.format("No private key item found for key '%s'", certificate.keyUuid()),
                        "Signing key could not be found."));

        CryptographicKeyItemOperationModel publicKeyItem = keyItems
                .stream()
                .filter(item -> item.keyType() == KeyType.PUBLIC_KEY)
                .findFirst()
                .orElseThrow(() -> new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                        String.format("No public key item found for key '%s'", certificate.keyUuid()),
                        "Signing key could not be found."));

        List<RequestAttribute> requestAttributes = signingScheme.signingOperationAttributes();

        SignatureAlgorithm signatureAlgorithm = resolveSignatureAlgorithm(privateKeyItem, publicKeyItem,
                requestAttributes);

        return new CryptographicOperationServiceSigner(cryptographicOperationService,
                SecuredParentUUID.fromUUID(certificate.tokenInstanceReferenceUuid()),
                SecuredUUID.fromUUID(certificate.tokenProfileUuid()), certificate.keyUuid(),
                privateKeyItem.keyItemUuid(), requestAttributes, signatureAlgorithm);
    }

    /**
     * A key algorithm and digest an operator may configure can name a signature algorithm the platform has no entry for
     * -- a SHA-1 digest, or a PQC parameter set outside the enum. That is a Signing Profile the operator can fix, so it
     * is refused as MISCONFIGURED rather than escaping as the unchecked throw a caller would log as a platform fault.
     */
    private static SignatureAlgorithm resolveSignatureAlgorithm(CryptographicKeyItemOperationModel privateKeyItem,
            CryptographicKeyItemOperationModel publicKeyItem, List<RequestAttribute> requestAttributes)
            throws SigningEngineException {
        String algorithmName = resolveSignatureAlgorithmName(privateKeyItem, publicKeyItem, requestAttributes);
        try {
            return SignatureAlgorithm.findByCode(algorithmName);
        } catch (ValidationException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "signing key algorithm '%s' and its signing attributes resolve to signature algorithm '%s', which the platform does not support"
                            .formatted(privateKeyItem.keyAlgorithm(), algorithmName),
                    e, "Signing key algorithm is not supported.");
        }
    }

    /** The signing attributes are operator-supplied, so a missing or unreadable one names no algorithm at all. */
    private static String resolveSignatureAlgorithmName(CryptographicKeyItemOperationModel privateKeyItem,
            CryptographicKeyItemOperationModel publicKeyItem, List<RequestAttribute> requestAttributes)
            throws SigningEngineException {
        try {
            return CryptographyUtil
                    .resolveSignatureAlgorithmName(privateKeyItem.keyAlgorithm(), requestAttributes,
                            publicKeyItem.pqcParameterSpecName());
        } catch (RuntimeException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "signing key algorithm '%s' and its signing attributes name no signature algorithm"
                            .formatted(privateKeyItem.keyAlgorithm()),
                    e, "Signing key algorithm is not supported.");
        }
    }
}

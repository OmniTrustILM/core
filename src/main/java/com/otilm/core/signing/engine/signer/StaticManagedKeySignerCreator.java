package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
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
     * Operator-supplied attributes can name a signature algorithm the platform has no entry for -- a SHA-1 digest, or a
     * PQC parameter set outside the enum. That is a Signing Profile the operator can fix, so it is refused as
     * MISCONFIGURED rather than escaping as the unchecked throw a caller would log as a platform fault.
     *
     * <p>
     * Resolution reaches a repository and, for a cryptography provider v2, the connector, so the failure classes are
     * kept apart rather than collapsed: a provider that was reached but did not deliver is a CONNECTOR_FAULT, and any
     * other unexpected defect is deliberately left to escape so the engine logs it with a stack trace instead of
     * reporting it as an operator-fixable setting.
     * </p>
     */
    private SignatureAlgorithm resolveSignatureAlgorithm(CryptographicKeyItemOperationModel privateKeyItem,
            CryptographicKeyItemOperationModel publicKeyItem, List<RequestAttribute> requestAttributes)
            throws SigningEngineException {
        try {
            return cryptographicOperationService
                    .resolveSignatureAlgorithm(privateKeyItem, publicKeyItem, requestAttributes);
        } catch (ValidationException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "signing key algorithm '%s' and its signing attributes name no signature algorithm the platform supports: %s"
                            .formatted(privateKeyItem.keyAlgorithm(), e.getMessage()),
                    e, "Signing key algorithm is not supported.");
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "no operation scope is recorded for signing key '%s': %s"
                            .formatted(privateKeyItem.keyUuid(), e.getMessage()),
                    e, "Internal error: signing configuration is invalid");
        } catch (ConnectorException e) {
            throw new SigningEngineException(SigningEngineFailure.CONNECTOR_FAULT,
                    "cryptography provider named no signature algorithm for signing key '%s': %s"
                            .formatted(privateKeyItem.keyUuid(), e.getMessage()),
                    e, "Internal error");
        }
    }
}

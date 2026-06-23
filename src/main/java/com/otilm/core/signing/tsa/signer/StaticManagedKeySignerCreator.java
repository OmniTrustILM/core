package com.otilm.core.signing.tsa.signer;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.crypto.CryptographicKeyItemModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.util.CryptographyUtil;
import org.springframework.stereotype.Component;

import java.util.List;

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
    public Signer create(ResolvedManagedScheme signingSchemeModel) throws TspException {
        ResolvedStaticKeyManagedSigning signingScheme = (ResolvedStaticKeyManagedSigning) signingSchemeModel;

        SigningCertificate certificate = signingScheme.certificate();
        if (certificate.keyUuid() == null) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                    String.format("No cryptographic key associated with certificate '%s'", certificate.commonName()),
                    "Signing key could not be found.");
        }

        List<CryptographicKeyItemModel> keyItems = signingScheme.keyItems();

        CryptographicKeyItemModel privateKeyItem = keyItems.stream()
                .filter(item -> item.keyType() == KeyType.PRIVATE_KEY)
                .findFirst()
                .orElseThrow(() -> new TspException(TspFailureInfo.SYSTEM_FAILURE,
                        String.format("No private key item found for key '%s'", certificate.keyUuid()),
                        "Signing key could not be found."));

        CryptographicKeyItemModel publicKeyItem = keyItems.stream()
                .filter(item -> item.keyType() == KeyType.PUBLIC_KEY)
                .findFirst()
                .orElseThrow(() -> new TspException(TspFailureInfo.SYSTEM_FAILURE,
                        String.format("No public key item found for key '%s'", certificate.keyUuid()),
                        "Signing key could not be found."));

        List<RequestAttribute> requestAttributes = signingScheme.signingOperationAttributes();

        String algorithmName = CryptographyUtil.resolveSignatureAlgorithmName(
                privateKeyItem.keyAlgorithm(), requestAttributes, publicKeyItem.pqcParameterSpecName());
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findByCode(algorithmName);

        return new CryptographicOperationServiceSigner(
                cryptographicOperationService,
                SecuredParentUUID.fromUUID(certificate.tokenInstanceReferenceUuid()),
                SecuredUUID.fromUUID(certificate.tokenProfileUuid()),
                certificate.keyUuid(),
                privateKeyItem.keyItemUuid(),
                requestAttributes,
                signatureAlgorithm
        );
    }
}

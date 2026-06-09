package com.czertainly.core.signing.tsa.signer;

import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.czertainly.core.model.crypto.CryptographicKeyItemModel;
import com.czertainly.core.model.signing.SigningCertificate;
import com.czertainly.core.model.signing.resolved.ResolvedManagedScheme;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CryptographicOperationService;
import com.czertainly.core.util.CryptographyUtil;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class StaticManagedKeySignerCreator implements SignerCreator {

    private final CryptographicOperationService cryptographicOperationService;

    public StaticManagedKeySignerCreator(CryptographicOperationService cryptographicOperationService) {
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

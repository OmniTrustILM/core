package com.otilm.core.signing.contentsigning.declaration;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import java.util.Optional;
import java.util.Set;

/** A family that omits its algorithm list accepts every algorithm the platform can sign with. */
public final class FamilyAlgorithms {

    private FamilyAlgorithms() {
    }

    public static Optional<Set<SignatureAlgorithm>> restriction(SignatureFamilyDeclarationDto family) {
        return Optional.ofNullable(family.getSignatureAlgorithms());
    }

    public static boolean accepts(SignatureFamilyDeclarationDto family, SignatureAlgorithm signatureAlgorithm) {
        return restriction(family).map(accepted -> accepted.contains(signatureAlgorithm)).orElse(true);
    }
}

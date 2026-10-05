package com.otilm.core.service.handler.key;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ResolvedSignatureAlgorithmTest {

    @Test
    void algorithmIdentifier_isThePlatformEntry_whenThePlatformHasOne() {
        // given
        ResolvedSignatureAlgorithm resolved = new ResolvedSignatureAlgorithm("not a JCA name",
                SignatureAlgorithm.SHA256_WITH_RSA_PSS);

        // when
        AlgorithmIdentifier identifier = resolved.algorithmIdentifier();

        // then
        assertEquals("1.2.840.113549.1.1.10", identifier.getAlgorithm().getId());
        RSASSAPSSparams parameters = RSASSAPSSparams.getInstance(identifier.getParameters());
        assertEquals("2.16.840.1.101.3.4.2.1", parameters.getHashAlgorithm().getAlgorithm().getId());
        assertEquals(32, parameters.getSaltLength().intValue());
    }

    @Test
    void algorithmIdentifier_isLookedUpByName_whenThePlatformHasNoEntry() {
        // given
        ResolvedSignatureAlgorithm resolved = new ResolvedSignatureAlgorithm("SHA3-256WITHRSA", null);

        // when
        AlgorithmIdentifier identifier = resolved.algorithmIdentifier();

        // then
        assertEquals("2.16.840.1.101.3.4.3.14", identifier.getAlgorithm().getId());
    }
}

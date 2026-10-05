package com.otilm.core.container;

import com.otilm.core.container.Pkcs12Mac.Integrity;
import com.otilm.core.key.normalization.DerivationBudget;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Pkcs12MacTest {

    private static final char[] EMPTY_PASSWORD = new char[0];

    @BeforeAll
    static void providers() {
        ContainerFixtures.registerProviders();
    }

    @Test
    void verify_triesAnEmptyPasswordAsOpenSslAndTheJdkEncodeItFirst() throws Exception {
        // given
        Pfx pfx = Pfx.getInstance(Pkcs12Fixtures.openSsl(Pkcs12Fixtures.OPENSSL_EMPTY_PASSWORD));
        DerivationBudget budget = budgetForOneMac(pfx);

        // when
        Integrity integrity = Pkcs12Mac.verify(pfx.getMacData(), authenticatedSafe(pfx), EMPTY_PASSWORD, budget);

        // then
        assertThat(integrity).isEqualTo(Integrity.TERMINATED_EMPTY_PASSWORD);
    }

    @Test
    void verify_triesAnEmptyPasswordAsBouncyCastleEncodesItSecond() throws Exception {
        // given
        Pfx pfx = Pfx
                .getInstance(Pkcs12Fixtures
                        .builder()
                        .certBag(ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Empty"), null, null)
                        .mac(EMPTY_PASSWORD, NISTObjectIdentifiers.id_sha256)
                        .build());
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        Integrity integrity = Pkcs12Mac.verify(pfx.getMacData(), authenticatedSafe(pfx), EMPTY_PASSWORD, budget);

        // then
        assertThat(integrity).isEqualTo(Integrity.PASSPHRASE);
    }

    /** A budget with room left for the MAC's derivation once, and not twice. */
    private static DerivationBudget budgetForOneMac(Pfx pfx) {
        DerivationBudget budget = DerivationBudget.forFile();
        budget
                .charge(BigInteger
                        .valueOf(DerivationBudget.FILE_ITERATIONS)
                        .subtract(pfx.getMacData().getIterationCount()));
        return budget;
    }

    private static byte[] authenticatedSafe(Pfx pfx) {
        return ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets();
    }
}

package com.czertainly.core.signing.tsa;

import com.czertainly.core.util.CertificateTestUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CertificateChainTest {

    static X509Certificate leafCert;
    static X509Certificate caCert;

    @BeforeAll
    static void createCertificates() throws Exception {
        leafCert = CertificateTestUtil.createTimestampingCertificate();
        caCert = CertificateTestUtil.createCACertificate();
    }

    // ── constructor ───────────────────────────────────────────────────────────

    @Test
    void constructor_throwsIllegalArgumentException_whenSigningCertificateIsNull() {
        // given
        X509Certificate nullCert = null;

        // when
        var exception = assertThrows(IllegalArgumentException.class,
                () -> new CertificateChain(nullCert, List.of(leafCert)));

        // then
        assertEquals("signingCertificate must not be null", exception.getMessage());
    }

    @Test
    void constructor_throwsIllegalArgumentException_whenChainDoesNotStartWithSigningCertificate() {
        // given - chain starts with caCert, but signingCertificate is leafCert
        var chain = List.of(caCert, leafCert);

        // when
        var exception = assertThrows(IllegalArgumentException.class,
                () -> new CertificateChain(leafCert, chain));

        // then
        assertEquals("chain must start with the signing certificate", exception.getMessage());
    }

    @Test
    void constructor_throwsIllegalArgumentException_whenChainIsEmpty() {
        // given
        var emptyChain = List.<X509Certificate>of();

        // when
        var exception = assertThrows(IllegalArgumentException.class,
                () -> new CertificateChain(leafCert, emptyChain));

        // then
        assertEquals("chain must start with the signing certificate", exception.getMessage());
    }

    @Test
    void constructor_throwsIllegalArgumentException_whenSigningCertificateIsACaCertificate() throws Exception {
        // given - a CA certificate cannot be used as the signing (end-entity) certificate
        var caCertAsLeaf = CertificateTestUtil.createCACertificate();
        var chain = List.of(caCertAsLeaf);

        // when
        var exception = assertThrows(IllegalArgumentException.class,
                () -> new CertificateChain(caCertAsLeaf, chain));

        // then
        assertEquals("signingCertificate must be an end-entity certificate, not a CA", exception.getMessage());
    }

    @Test
    void constructor_throwsIllegalArgumentException_whenIntermediateCertificateIsNotACaCertificate() throws Exception {
        // given - a non-CA certificate in the intermediate position is invalid
        var anotherLeafCert = CertificateTestUtil.createTimestampingCertificate();
        var chain = List.of(leafCert, anotherLeafCert);

        // when
        var exception = assertThrows(IllegalArgumentException.class,
                () -> new CertificateChain(leafCert, chain));

        // then
        assertEquals("certificate at index 1 in the chain must be a CA certificate", exception.getMessage());
    }

    @Test
    void constructor_setsSigningCertificateAndChain_whenChainStartsWithSigningCertificate() {
        // given
        var chain = List.of(leafCert, caCert);

        // when
        var certificateChain = new CertificateChain(leafCert, chain);

        // then
        assertEquals(leafCert, certificateChain.signingCertificate());
        assertEquals(chain, certificateChain.chain());
    }

    @Test
    void constructor_returnsImmutableChain() {
        // given - a mutable list that could be modified after construction
        var mutableList = new ArrayList<>(List.of(leafCert, caCert));
        var certificateChain = new CertificateChain(leafCert, mutableList);

        // when
        mutableList.add(caCert);

        // then - chain inside the record must not reflect the external mutation
        assertEquals(2, certificateChain.chain().size());
    }

    // ── of(X509Certificate) ───────────────────────────────────────────────────

    @Test
    void ofSingleCert_setsSigningCertificateToGivenCertificate() {
        // when
        var certificateChain = CertificateChain.of(leafCert);

        // then
        assertEquals(leafCert, certificateChain.signingCertificate());
    }

    @Test
    void ofSingleCert_setsChainToSingletonListContainingTheCertificate() {
        // when
        var certificateChain = CertificateChain.of(leafCert);

        // then
        assertEquals(List.of(leafCert), certificateChain.chain());
    }

    // ── of(List<X509Certificate>) ─────────────────────────────────────────────

    @Test
    void ofList_setsSigningCertificateToFirstElementOfTheChain() {
        // given
        var chain = List.of(leafCert, caCert);

        // when
        var certificateChain = CertificateChain.of(chain);

        // then
        assertEquals(leafCert, certificateChain.signingCertificate());
    }

    @Test
    void ofList_setsChainToTheGivenList() {
        // given
        var chain = List.of(leafCert, caCert);

        // when
        var certificateChain = CertificateChain.of(chain);

        // then
        assertEquals(chain, certificateChain.chain());
    }
}

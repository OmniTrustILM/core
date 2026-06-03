package com.czertainly.core.signing.tsa;

import com.czertainly.core.util.CertificateTestUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateChainTest {

    static X509Certificate leafCert;
    static X509Certificate caCert;

    @BeforeAll
    static void createCertificates() throws Exception {
        leafCert = CertificateTestUtil.createTimestampingCertificate();
        caCert = CertificateTestUtil.createCACertificate();
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    @Nested
    class Constructor {

        @Test
        void throwsIllegalArgumentException_whenSigningCertificateIsNull() {
            // given
            X509Certificate nullCert = null;
            List<X509Certificate> leafChain = List.of(leafCert);

            // when / then
            assertThatThrownBy(() -> new CertificateChain(nullCert, leafChain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("signingCertificate must not be null");
        }

        @Test
        void throwsIllegalArgumentException_whenChainDoesNotStartWithSigningCertificate() {
            // given — chain starts with caCert, but signingCertificate is leafCert
            var chain = List.of(caCert, leafCert);

            // when / then
            assertThatThrownBy(() -> new CertificateChain(leafCert, chain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("chain must start with the signing certificate");
        }

        @Test
        void throwsIllegalArgumentException_whenChainIsEmpty() {
            // given
            var emptyChain = List.<X509Certificate>of();

            // when / then
            assertThatThrownBy(() -> new CertificateChain(leafCert, emptyChain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("chain must start with the signing certificate");
        }

        @Test
        void throwsIllegalArgumentException_whenSigningCertificateIsACaCertificate() throws Exception {
            // given — a CA certificate cannot be used as the signing (end-entity) certificate
            var caCertAsLeaf = CertificateTestUtil.createCACertificate();
            var chain = List.of(caCertAsLeaf);

            // when / then
            assertThatThrownBy(() -> new CertificateChain(caCertAsLeaf, chain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("signingCertificate must be an end-entity certificate, not a CA");
        }

        @Test
        void throwsIllegalArgumentException_whenIntermediateCertificateIsNotACaCertificate() throws Exception {
            // given — a non-CA certificate in the intermediate position is invalid
            var anotherLeafCert = CertificateTestUtil.createTimestampingCertificate();
            var chain = List.of(leafCert, anotherLeafCert);

            // when / then
            assertThatThrownBy(() -> new CertificateChain(leafCert, chain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("certificate at index 1 in the chain must be a CA certificate");
        }

        @Test
        void setsSigningCertificateAndChain_whenChainStartsWithSigningCertificate() {
            // given
            var chain = List.of(leafCert, caCert);

            // when
            var certificateChain = new CertificateChain(leafCert, chain);

            // then
            assertThat(certificateChain.signingCertificate()).isEqualTo(leafCert);
            assertThat(certificateChain.chain()).isEqualTo(chain);
        }

        @Test
        void returnsImmutableChain() {
            // given — a mutable list that could be modified after construction
            var mutableList = new ArrayList<>(List.of(leafCert, caCert));
            var certificateChain = new CertificateChain(leafCert, mutableList);

            // when
            mutableList.add(caCert);

            // then — chain inside the record must not reflect the external mutation
            assertThat(certificateChain.chain()).hasSize(2);
        }
    }

    // ── OfSingleCertificate ───────────────────────────────────────────────────

    @Nested
    class OfSingleCertificate {

        @Test
        void setsSigningCertificateToGivenCertificate() {
            // when
            var certificateChain = CertificateChain.of(leafCert);

            // then
            assertThat(certificateChain.signingCertificate()).isEqualTo(leafCert);
        }

        @Test
        void setsChainToSingletonListContainingTheCertificate() {
            // when
            var certificateChain = CertificateChain.of(leafCert);

            // then
            assertThat(certificateChain.chain()).isEqualTo(List.of(leafCert));
        }
    }

    // ── OfCertificateList ─────────────────────────────────────────────────────

    @Nested
    class OfCertificateList {

        @Test
        void setsSigningCertificateToFirstElementOfTheChain() {
            // given
            var chain = List.of(leafCert, caCert);

            // when
            var certificateChain = CertificateChain.of(chain);

            // then
            assertThat(certificateChain.signingCertificate()).isEqualTo(leafCert);
        }

        @Test
        void setsChainToTheGivenList() {
            // given
            var chain = List.of(leafCert, caCert);

            // when
            var certificateChain = CertificateChain.of(chain);

            // then
            assertThat(certificateChain.chain()).isEqualTo(chain);
        }
    }
}

package com.otilm.core.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.CertificateGeneratorHelper.CertificateChainInfo;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class OcspUtilTest {

    private static CertificateChainInfo chain;

    @BeforeAll
    static void generateChain() throws Exception {
        chain = CertificateGeneratorHelper
                .generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Ocsp-Util-Ca", "CN=Ocsp-Util-EndEntity", null);
    }

    @Test
    void returnsCaIssuerUrisInOrder_whenAiaAlsoContainsOcspAndDirectoryNames() throws Exception {
        // given
        String ldapUrl = "ldap:///CN=Issuer?cACertificate;binary";
        String httpUrl = "http://issuer.example/ca.p7c";
        AuthorityInformationAccess aia = new AuthorityInformationAccess(new AccessDescription[]{
                new AccessDescription(AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example/")),
                new AccessDescription(AccessDescription.id_ad_caIssuers,
                        new GeneralName(GeneralName.uniformResourceIdentifier, ldapUrl)),
                new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(new X500Name("CN=Issuer"))),
                new AccessDescription(AccessDescription.id_ad_caIssuers,
                        new GeneralName(GeneralName.uniformResourceIdentifier, httpUrl))});
        X509Certificate certificate = CertificateGeneratorHelper
                .generateEndEntityCertificateWithAuthorityInfoAccess(chain.getCaCertificateKeyPair(),
                        chain.getCaCertificate(), chain.getEndEntityCertificateKeyPair(), "CN=AIA-Leaf",
                        aia.getEncoded());

        // when
        List<String> issuerUrls = OcspUtil.getCaIssuerUrlsFromAia(certificate);

        // then
        assertThat(issuerUrls).containsExactly(ldapUrl, httpUrl);
    }

    @Test
    void returnsNoCaIssuerUrls_whenTheExtensionIsAbsent() throws Exception {
        // given — the root CA certificate has no AIA extension

        // when
        List<String> issuerUrls = OcspUtil.getCaIssuerUrlsFromAia(chain.getCaCertificate());

        // then
        assertThat(issuerUrls).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("malformedAuthorityInfoAccess")
    void throwsIoException_whenCaIssuerExtensionValueIsMalformed(byte[] malformedAuthorityInfoAccess) throws Exception {
        // given
        X509Certificate certificate = CertificateGeneratorHelper
                .generateEndEntityCertificateWithAuthorityInfoAccess(chain.getCaCertificateKeyPair(),
                        chain.getCaCertificate(), chain.getEndEntityCertificateKeyPair(), "CN=AIA-Leaf",
                        malformedAuthorityInfoAccess);

        // when
        ThrowingCallable readIssuerUrls = () -> OcspUtil.getCaIssuerUrlsFromAia(certificate);

        // then
        assertThatThrownBy(readIssuerUrls)
                .isInstanceOfSatisfying(IOException.class, exception -> assertThat(exception.getCause()).isNotNull())
                .hasMessageContaining("The authorityInfoAccess extension is malformed");
    }

    @Test
    void returnsCaIssuerUrl_whenExtensionValueIsBerEncoded() throws Exception {
        // given
        var issuerUrl = "http://issuer.example/ca.p7c";
        var issuerAccess = new AccessDescription(AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, issuerUrl));
        byte[] indefiniteLengthAuthorityInfoAccess = new BERSequence(issuerAccess).getEncoded();
        X509Certificate certificate = CertificateGeneratorHelper
                .generateEndEntityCertificateWithAuthorityInfoAccess(chain.getCaCertificateKeyPair(),
                        chain.getCaCertificate(), chain.getEndEntityCertificateKeyPair(), "CN=AIA-Leaf",
                        indefiniteLengthAuthorityInfoAccess);

        // when
        List<String> issuerUrls = OcspUtil.getCaIssuerUrlsFromAia(certificate);

        // then
        assertThat(issuerUrls).containsExactly(issuerUrl);
    }

    @ParameterizedTest
    @MethodSource("malformedAuthorityInfoAccess")
    void throwsIoException_whenExtensionValueIsMalformed(byte[] malformedAuthorityInfoAccess) throws Exception {
        // given
        X509Certificate certificate = CertificateGeneratorHelper
                .generateEndEntityCertificateWithAuthorityInfoAccess(chain.getCaCertificateKeyPair(),
                        chain.getCaCertificate(), chain.getEndEntityCertificateKeyPair(), "CN=Ocsp-Util-EndEntity",
                        malformedAuthorityInfoAccess);

        // when
        ThrowingCallable readOcspUrls = () -> OcspUtil.getOcspUrlFromCertificate(certificate);

        // then
        assertThatThrownBy(readOcspUrls)
                .isInstanceOfSatisfying(IOException.class, exception -> assertThat(exception.getCause()).isNotNull())
                .hasMessage("The authorityInfoAccess extension is malformed");
    }

    @Test
    void returnsOcspUrl_whenExtensionValueIsBerEncoded() throws Exception {
        // given
        var ocspUrl = "http://ocsp.example/";
        var ocspAccess = new AccessDescription(AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl));
        byte[] indefiniteLengthAuthorityInfoAccess = new BERSequence(ocspAccess).getEncoded();
        X509Certificate certificate = CertificateGeneratorHelper
                .generateEndEntityCertificateWithAuthorityInfoAccess(chain.getCaCertificateKeyPair(),
                        chain.getCaCertificate(), chain.getEndEntityCertificateKeyPair(), "CN=Ocsp-Util-EndEntity",
                        indefiniteLengthAuthorityInfoAccess);

        // when
        List<String> ocspUrls = OcspUtil.getOcspUrlFromCertificate(certificate);

        // then
        assertThat(ocspUrls).containsExactly(ocspUrl);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<byte[]>> malformedAuthorityInfoAccess() {
        return Stream
                .of(named("no value", new byte[0]),
                        named("a value that is not a sequence", HexFormat.of().parseHex("020101")),
                        named("an empty list of access descriptions", HexFormat.of().parseHex("3000")),
                        named("an access location tagged as a URI but constructed",
                                HexFormat.of().parseHex("3012301006082b06010505073001a60416027878")),
                        named("an EDI party name without its party name",
                                HexFormat.of().parseHex("3013301106082b06010505073001a505a0030c0141")),
                        named("a length beyond the end of the value", HexFormat.of().parseHex("30053003")));
    }
}

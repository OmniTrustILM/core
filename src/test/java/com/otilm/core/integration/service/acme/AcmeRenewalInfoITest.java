package com.otilm.core.integration.service.acme;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.interfaces.core.acme.AcmeController;
import com.otilm.api.interfaces.core.acme.AcmeRaProfileController;
import com.otilm.api.model.core.acme.Directory;
import com.otilm.api.model.core.acme.RenewalInfo;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.AriCertId;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What the ACME server answers on renewal-info (RFC 9773): the window of an issued certificate of the profile's RA
 * profile, in both URL families, and nothing for anything else.
 */
class AcmeRenewalInfoITest extends BaseSpringBootTest {

    private static final String PROFILE_NAME = "ariProfile";
    private static final Instant WINDOW_START = Instant.parse("2026-03-09T00:00:00Z");
    private static final Instant WINDOW_END = Instant.parse("2026-03-10T12:30:00Z");

    @Autowired
    private AcmeController acmeController;
    @Autowired
    private AcmeRaProfileController acmeRaProfileController;
    @Autowired
    private AcmeExternalService acmeService;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;

    private WireMockServer connector;
    private RaProfile raProfile;
    private AcmeProfile acmeProfile;
    private KeyPair issuerKeys;
    private byte[] issuerKeyIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        connector = new WireMockServer(LoopbackWireMock.options());
        connector.start();
        raProfile = AuthorityFixtures
                .v3Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), connector)
                .raProfile();
        acmeProfile = acmeProfile(true);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        issuerKeys = generator.generateKeyPair();
        issuerKeyIdentifier = new JcaX509ExtensionUtils()
                .createAuthorityKeyIdentifier(issuerKeys.getPublic())
                .getKeyIdentifier();
    }

    @AfterEach
    void tearDown() {
        connector.stop();
    }

    @Test
    void answersTheWindowThroughBothUrlFamilies() throws Exception {
        Certificate certificate = issuedCertificate(new BigInteger("8a01", 16), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.POLICY, "https://ca.example/why");
        String certId = idOf(certificate);
        assertThat(AriCertId.parse(certId).serialHex()).isEqualTo("8a01");

        ResponseEntity<RenewalInfo> byAcmeProfile = acmeController.getRenewalInfo(PROFILE_NAME, certId);
        ResponseEntity<RenewalInfo> byRaProfile = acmeRaProfileController.getRenewalInfo(raProfile.getName(), certId);

        for (ResponseEntity<RenewalInfo> response : List.of(byAcmeProfile, byRaProfile)) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody().getSuggestedWindow().getStart()).isEqualTo("2026-03-09T00:00:00Z");
            assertThat(response.getBody().getSuggestedWindow().getEnd()).isEqualTo("2026-03-10T12:30:00Z");
            assertThat(response.getBody().getExplanationUrl()).isEqualTo("https://ca.example/why");
            assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("21600");
            assertThat(response.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).contains("max-age=21600");
        }
    }

    @Test
    void capsRetryAfterAtAnHourForAForcedWindow() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(77), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.FORCED, null);

        ResponseEntity<RenewalInfo> response = acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate));

        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("3600");
        assertThat(response.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).contains("max-age=3600");
        assertThat(response.getBody().getExplanationUrl()).isNull();
    }

    @Test
    void keepsAShortProfileRetryAfterForAForcedWindow() throws Exception {
        acmeProfile.setRenewalInfoRetryAfter(600);
        acmeProfileRepository.save(acmeProfile);
        Certificate certificate = issuedCertificate(BigInteger.valueOf(78), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.FORCED, null);

        ResponseEntity<RenewalInfo> response = acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate));

        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("600");
    }

    @Test
    void answers404_whenTheProfileDoesNotServeRenewalInformation() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(79), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.POLICY, null);
        acmeProfile.setRenewalInfoEnabled(false);
        acmeProfileRepository.save(acmeProfile);

        assertThat(acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(acmeRaProfileController.getRenewalInfo(raProfile.getName(), idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenTheRaProfileIsDisabled_inBothFamilies() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(88), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.POLICY, null);
        raProfile.setEnabled(false);
        raProfileRepository.save(raProfile);

        assertThat(acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(acmeRaProfileController.getRenewalInfo(raProfile.getName(), idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenTheAcmeProfileIsDisabled_evenWithRenewalInformationOn() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(89), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.POLICY, null);
        acmeProfile.setEnabled(false);
        acmeProfileRepository.save(acmeProfile);

        assertThat(acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(acmeRaProfileController.getRenewalInfo(raProfile.getName(), idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenTheProfileIsUnknown() throws Exception {
        assertThat(acmeController.getRenewalInfo("nope", "AQID.AQID").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(acmeRaProfileController.getRenewalInfo("nope", "AQID.AQID").getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenTheCertificateIsUnknown() throws Exception {
        ResponseEntity<RenewalInfo> response = acmeController
                .getRenewalInfo(PROFILE_NAME, AriCertId.of(certificate(BigInteger.valueOf(404), issuerKeyIdentifier)));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenThereIsNoRenewalRow() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(80), issuerKeyIdentifier);

        assertThat(acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenTheRowHasNoWindow() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(81), issuerKeyIdentifier);
        CertificateRenewalInfo info = window(certificate, RenewalWindowSource.POLICY, null);
        info.setWindowStart(null);
        info.setWindowEnd(null);
        info.setSource(null);
        renewalInfoRepository.save(info);

        assertThat(acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenTheAuthorityKeyIdentifierDiffers() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(82), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.POLICY, null);
        String otherIssuer = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{1, 2, 3, 4}) + ".Ug";

        assertThat(acmeController.getRenewalInfo(PROFILE_NAME, otherIssuer).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void answers404_whenTheCertificateIsNotIssued_isArchived_orBelongsToAnotherRaProfile() throws Exception {
        Certificate revoked = issuedCertificate(BigInteger.valueOf(83), issuerKeyIdentifier);
        revoked.setState(CertificateState.REVOKED);
        certificateRepository.save(revoked);
        window(revoked, RenewalWindowSource.POLICY, null);
        Certificate archived = issuedCertificate(BigInteger.valueOf(84), issuerKeyIdentifier);
        archived.setArchived(true);
        certificateRepository.save(archived);
        window(archived, RenewalWindowSource.POLICY, null);
        Certificate elsewhere = issuedCertificate(BigInteger.valueOf(85), issuerKeyIdentifier);
        elsewhere.setRaProfile(null);
        elsewhere.setRaProfileUuid(null);
        certificateRepository.save(elsewhere);
        window(elsewhere, RenewalWindowSource.POLICY, null);

        for (Certificate certificate : List.of(revoked, archived, elsewhere)) {
            assertThat(acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate)).getStatusCode())
                    .as(certificate.getSerialNumber())
                    .isEqualTo(HttpStatus.NOT_FOUND);
        }
    }

    @Test
    void picksTheCandidateWhoseIssuerMatches_whenSerialNumbersCollideAcrossIssuers() throws Exception {
        byte[] otherKeyIdentifier = {9, 9, 9, 9};
        Certificate other = issuedCertificate(BigInteger.valueOf(86), otherKeyIdentifier);
        Certificate wanted = issuedCertificate(BigInteger.valueOf(86), issuerKeyIdentifier);
        window(other, RenewalWindowSource.FORCED, "https://ca.example/other");
        window(wanted, RenewalWindowSource.POLICY, "https://ca.example/wanted");

        ResponseEntity<RenewalInfo> response = acmeController.getRenewalInfo(PROFILE_NAME, idOf(wanted));

        assertThat(response.getBody().getExplanationUrl()).isEqualTo("https://ca.example/wanted");
    }

    @Test
    void answers400Malformed_forABadCertificateIdentifier() {
        for (String certId : new String[]{"nodot", ".AQID", "AQID.", "AQ+D.AQID", "AQID.AQID=", "A.B.C"}) {
            assertThatThrownBy(() -> acmeController.getRenewalInfo(PROFILE_NAME, certId))
                    .as(certId)
                    .isInstanceOfSatisfying(AcmeProblemDocumentException.class, e -> {
                        assertThat(e.getHttpStatusCode()).isEqualTo(400);
                        assertThat(e.getProblemDocument().getType()).isEqualTo("urn:ietf:params:acme:error:malformed");
                    });
        }
    }

    @Test
    void neverCallsTheConnector() throws Exception {
        Certificate certificate = issuedCertificate(BigInteger.valueOf(87), issuerKeyIdentifier);
        window(certificate, RenewalWindowSource.POLICY, null);

        acmeController.getRenewalInfo(PROFILE_NAME, idOf(certificate));
        acmeRaProfileController.getRenewalInfo(raProfile.getName(), idOf(certificate));
        acmeController
                .getRenewalInfo(PROFILE_NAME, AriCertId.of(certificate(BigInteger.valueOf(1), issuerKeyIdentifier)));

        assertThat(connector.getAllServeEvents()).isEmpty();
    }

    @Test
    void directoryAdvertisesRenewalInfoInBothFamilies_onlyWhenEnabled() throws Exception {
        Directory enabledAcme = acmeService
                .getDirectory(PROFILE_NAME, URI.create("http://localhost/"), false)
                .getBody();
        Directory enabledRa = acmeService
                .getDirectory(raProfile.getName(), URI.create("http://localhost/"), true)
                .getBody();

        assertThat(enabledAcme.getRenewalInfo()).endsWith("/v1/protocols/acme/" + PROFILE_NAME + "/renewal-info");
        assertThat(enabledRa.getRenewalInfo())
                .endsWith("/v1/protocols/acme/raProfile/" + raProfile.getName() + "/renewal-info");

        acmeProfile.setRenewalInfoEnabled(false);
        acmeProfileRepository.save(acmeProfile);

        assertThat(acmeService
                .getDirectory(PROFILE_NAME, URI.create("http://localhost/"), false)
                .getBody()
                .getRenewalInfo()).isNull();
        assertThat(acmeService
                .getDirectory(raProfile.getName(), URI.create("http://localhost/"), true)
                .getBody()
                .getRenewalInfo()).isNull();
    }

    private AcmeProfile acmeProfile(boolean renewalInfoEnabled) {
        AcmeProfile profile = new AcmeProfile();
        profile.setName(PROFILE_NAME);
        profile.setEnabled(true);
        profile.setDisableNewOrders(false);
        profile.setRaProfile(raProfile);
        profile.setRenewalInfoEnabled(renewalInfoEnabled);
        profile = acmeProfileRepository.save(profile);
        raProfile.setAcmeProfile(profile);
        raProfileRepository.save(raProfile);
        return profile;
    }

    private Certificate issuedCertificate(BigInteger serial, byte[] keyIdentifier) throws Exception {
        X509Certificate x509 = certificate(serial, keyIdentifier);
        CertificateContent content = new CertificateContent();
        content.setContent(Base64.getEncoder().encodeToString(x509.getEncoded()));
        content = certificateContentRepository.save(content);
        Certificate certificate = com.otilm.core.util.builders.CertificateBuilder
                .aCertificate()
                .withSubjectDn("CN=ari-test")
                .withSerialNumber(serial.toString(16))
                .withFingerprint(UUID.randomUUID().toString())
                .withState(CertificateState.ISSUED)
                .withArchived(false)
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withRaProfile(raProfile)
                .withRaProfileUuid(raProfile.getUuid())
                .withNotBefore(Date.from(Instant.now().minus(10, ChronoUnit.DAYS)))
                .withNotAfter(Date.from(Instant.now().plus(20, ChronoUnit.DAYS)))
                .build();
        return certificateRepository.save(certificate);
    }

    private X509Certificate certificate(BigInteger serial, byte[] keyIdentifier) throws Exception {
        X500Name name = new X500Name("CN=ari-test");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial,
                new Date(System.currentTimeMillis() - 1000), new Date(System.currentTimeMillis() + 100000), name,
                issuerKeys.getPublic());
        builder.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(keyIdentifier));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
    }

    private CertificateRenewalInfo window(Certificate certificate, RenewalWindowSource source, String explanationUrl) {
        CertificateRenewalInfo info = new CertificateRenewalInfo();
        info.setCertificateUuid(certificate.getUuid());
        info.setWindowStart(WINDOW_START);
        info.setWindowEnd(WINDOW_END);
        info.setExplanationUrl(explanationUrl);
        info.setSource(source);
        info.setUpdatedAt(Instant.now());
        return renewalInfoRepository.save(info);
    }

    private String idOf(Certificate certificate) throws Exception {
        return AriCertId.of(com.otilm.core.util.CertificateUtil.getX509Certificate(certificate.getContentData()));
    }
}

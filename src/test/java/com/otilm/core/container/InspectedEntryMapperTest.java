package com.otilm.core.container;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.inspection.InspectedEntryDto;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.util.CertificateUtil;
import java.security.KeyPair;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.otilm.core.container.ContainerFixtures.LF;
import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;

class InspectedEntryMapperTest {

    private static ContainerReader reader;

    private static Chain chain;

    @BeforeAll
    static void fixtures() throws Exception {
        ContainerFixtures.registerProviders();
        // The distinguished names are rendered in the platform's style, which reads the OID registry.
        for (OidCategory category : OidCategory.values()) {
            if (OidHandler.getOidCache(category) == null) {
                OidHandler.cacheOidCategory(category, new HashMap<>());
            }
        }
        reader = ContainerFixtures.reader();
        chain = ContainerFixtures.rsaChain();
    }

    @Test
    void map_describesACertificateAsTheInventoryRecordsIt() throws Exception {
        // given
        GeneralNames names = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "leaf.example.com"),
                new GeneralName(GeneralName.rfc822Name, "leaf@example.com"),
                new GeneralName(GeneralName.iPAddress, "10.0.0.1"),
                new GeneralName(GeneralName.dNSName, "www.example.com")});
        X509CertificateHolder certificate = ContainerFixtures
                .selfSignedWithExtension(ContainerFixtures.ec(), "C=CZ,O=Example,CN=Leaf",
                        Extension.subjectAlternativeName, names.getEncoded());
        Certificate recorded = new Certificate();
        CertificateUtil
                .prepareIssuedCertificate(recorded, new JcaX509CertificateConverter().getCertificate(certificate));
        ContainerEntry entry = onlyEntryOf(ContainerFixtures.pem(LF, certificate));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getEntryReference()).isEqualTo(sha256(certificate.getEncoded()));
        assertThat(inspected.getKind()).isEqualTo(InspectedEntryKind.CERTIFICATE);
        assertThat(inspected.getSubjectDn()).isEqualTo("CN=Leaf, O=Example, C=CZ").isEqualTo(recorded.getSubjectDn());
        assertThat(inspected.getIssuerDn()).isEqualTo(recorded.getIssuerDn());
        assertThat(inspected.getSerialNumber()).isEqualTo(recorded.getSerialNumber());
        assertThat(inspected.getFingerprint()).isEqualTo(sha256(certificate.getEncoded()));
        assertThat(inspected.getNotBefore()).isEqualTo(certificate.getNotBefore().toInstant().atOffset(ZoneOffset.UTC));
        assertThat(inspected.getNotAfter()).isEqualTo(certificate.getNotAfter().toInstant().atOffset(ZoneOffset.UTC));
        assertThat(List.of(inspected.getNotBefore().getOffset(), inspected.getNotAfter().getOffset()))
                .containsOnly(ZoneOffset.UTC);
        assertThat(inspected.getSubjectAlternativeNames())
                .containsExactly("dNSName:leaf.example.com", "dNSName:www.example.com", "iPAddress:10.0.0.1",
                        "rfc822Name:leaf@example.com");
        assertThat(inspected.getKeyAlgorithm()).isNull();
        assertThat(inspected.getChainLength()).isNull();
        assertThat(inspected.getImportable()).isNull();
        assertThat(inspected.getNotImportableReason()).isNull();
    }

    @Test
    void map_describesAKeyPairByItsLeafAndCountsTheLeafAndItsIssuers() throws Exception {
        // given
        ContainerEntry entry = onlyEntryOf(ContainerFixtures
                .pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()), chain.leaf(), chain.intermediate(),
                        chain.root()));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getEntryReference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
        assertThat(inspected.getKind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(inspected.getSubjectDn()).isEqualTo("CN=Leaf");
        assertThat(inspected.getIssuerDn()).isEqualTo("CN=Intermediate");
        assertThat(inspected.getSerialNumber()).isEqualTo(chain.leaf().getSerialNumber().toString(16));
        assertThat(inspected.getFingerprint()).isEqualTo(sha256(chain.leaf().getEncoded()));
        assertThat(inspected.getSubjectAlternativeNames()).isEmpty();
        assertThat(inspected.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(inspected.getKeyLength()).isEqualTo(2048);
        assertThat(inspected.getChainLength()).isEqualTo(3);
    }

    @Test
    void map_describesAPrivateKeyWithoutACertificate() throws Exception {
        // given
        KeyPair key = ContainerFixtures.ec();
        ContainerEntry entry = onlyEntryOf(ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(key)));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getEntryReference()).isEqualTo(sha256(key.getPublic().getEncoded()));
        assertThat(inspected.getKind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
        assertThat(inspected.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.ECDSA);
        assertThat(inspected.getKeyLength()).isEqualTo(256);
        assertThat(inspected.getSubjectDn()).isNull();
        assertThat(inspected.getFingerprint()).isNull();
        assertThat(inspected.getChainLength()).isNull();
    }

    @Test
    void map_leavesOutTheAlgorithmOfAKeyThePlatformDoesNotSupport() throws Exception {
        // given
        ContainerEntry entry = onlyEntryOf(
                ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(ContainerFixtures.ed25519())));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getKind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
        assertThat(inspected.getKeyAlgorithm()).isNull();
        assertThat(inspected.getKeyLength()).isNull();
    }

    @Test
    void map_describesASecretKey() {
        // given
        KeyEntry entry = new KeyEntry("ab".repeat(32), "wrapping key", new byte[32],
                new KeyDescription(KeyRequestType.SECRET, KeyAlgorithm.AES, 256, null, null), null, List.of(), true);

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getEntryReference()).isEqualTo("ab".repeat(32));
        assertThat(inspected.getKind()).isEqualTo(InspectedEntryKind.SECRET_KEY);
        assertThat(inspected.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.AES);
        assertThat(inspected.getKeyLength()).isEqualTo(256);
        assertThat(inspected.getSubjectDn()).isNull();
        assertThat(inspected.getChainLength()).isNull();
    }

    @Test
    void map_describesASigningRequestByItsSubjectAndKey() throws Exception {
        // given
        PKCS10CertificationRequest request = ContainerFixtures.signingRequest(ContainerFixtures.ec());
        ContainerEntry entry = onlyEntryOf(ContainerFixtures.pem(LF, request));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getEntryReference()).isEqualTo(sha256(request.getEncoded()));
        assertThat(inspected.getKind()).isEqualTo(InspectedEntryKind.SIGNING_REQUEST);
        assertThat(inspected.getSubjectDn()).isEqualTo("CN=Request");
        assertThat(inspected.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.ECDSA);
        assertThat(inspected.getKeyLength()).isEqualTo(256);
        assertThat(inspected.getIssuerDn()).isNull();
        assertThat(inspected.getFingerprint()).isNull();
    }

    @Test
    void map_leavesOutTheKeyOfASigningRequestWhoseAlgorithmThePlatformDoesNotName() throws Exception {
        // given
        ContainerEntry entry = onlyEntryOf(
                ContainerFixtures.pem(LF, ContainerFixtures.signingRequest(ContainerFixtures.ed25519())));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getSubjectDn()).isEqualTo("CN=Request");
        assertThat(inspected.getKeyAlgorithm()).isNull();
        assertThat(inspected.getKeyLength()).isNull();
    }

    @Test
    void map_describesASigningRequestWhoseKeyCannotBeReadByItsSubject() throws Exception {
        // given
        SubjectPublicKeyInfo unreadableKey = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1")), new byte[]{1, 2, 3});
        PKCS10CertificationRequest request = new PKCS10CertificationRequestBuilder(new X500Name("CN=Request"),
                unreadableKey)
                .build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(ContainerFixtures.ec().getPrivate()));
        ContainerEntry entry = onlyEntryOf(ContainerFixtures.pem(LF, request));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getKind()).isEqualTo(InspectedEntryKind.SIGNING_REQUEST);
        assertThat(inspected.getSubjectDn()).isEqualTo("CN=Request");
        assertThat(inspected.getKeyAlgorithm()).isNull();
        assertThat(inspected.getKeyLength()).isNull();
    }

    /** A file may hold a certificate the platform cannot read as X.509, whose names it then cannot tell. */
    @Test
    void map_leavesOutTheNamesOfACertificateThePlatformCannotRead() throws Exception {
        // given
        X509CertificateHolder damaged = ContainerFixtures
                .selfSignedWithExtension(ContainerFixtures.ec(), "CN=Damaged", Extension.keyUsage,
                        new byte[]{0x04, 0x00});
        ContainerEntry entry = onlyEntryOf(ContainerFixtures.pem(LF, damaged));

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getSubjectDn()).isEqualTo("CN=Damaged");
        assertThat(inspected.getFingerprint()).isEqualTo(sha256(damaged.getEncoded()));
        assertThat(inspected.getSubjectAlternativeNames()).isNull();
    }

    @Test
    void map_namesACertificateByItsAlias() throws Exception {
        // given
        X509CertificateHolder certificate = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Root");
        CertificateEntry read = (CertificateEntry) onlyEntryOf(ContainerFixtures.pem(LF, certificate));
        ContainerEntry entry = new CertificateEntry(read.reference(), "root-ca", read.certificate());

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getAlias()).isEqualTo("root-ca");
    }

    @Test
    void map_namesAKeyByItsAlias() throws Exception {
        // given
        KeyEntry read = (KeyEntry) onlyEntryOf(
                ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()), chain.leaf()));
        ContainerEntry entry = new KeyEntry(read.reference(), "web-server-01", read.keyFile(), read.description(),
                read.leaf(), read.issuers(), read.secret());

        // when
        InspectedEntryDto inspected = InspectedEntryMapper.map(entry);

        // then
        assertThat(inspected.getAlias()).isEqualTo("web-server-01");
    }

    private static ContainerEntry onlyEntryOf(byte[] file) {
        List<ContainerEntry> entries = reader.read(file, null).entries();
        assertThat(entries).hasSize(1);
        return entries.getFirst();
    }
}

package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.certificate.QcType;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CertificateUtilTest {

    @BeforeAll
    static void initOidHandler() {
        // Seed the cache with an empty map so the class can be loaded outside a Spring context.
        for (OidCategory category : OidCategory.values()) {
            if (OidHandler.getOidCache(category) == null) {
                OidHandler.cacheOidCategory(category, new HashMap<>());
            }
        }
    }

    private static final String KEYSTORE_REFUSAL_MESSAGE = "The file is a keystore. Import it with the certificate"
            + " import operation.";

    private static final String VALID_SAN_STRING = "{\"dNSName\":[\"domain.com\"],\"directoryName\":[],\"ediPartyName\":[],\"iPAddress\":[\"192.168.10.10\"],\"otherName\":[\"1.2.3.4=example othername\"],\"registeredID\":[],\"rfc822Name\":[],\"uniformResourceIdentifier\":[],\"x400Address\":[]}";

    private static final Map<String, List<String>> VALID_SAN_MAP = Map
            .of("registeredID", List.of(), "ediPartyName", List.of(), "iPAddress", List.of("192.168.10.10"),
                    "x400Address", List.of(), "rfc822Name", List.of(), "otherName",
                    List.of("1.2.3.4=example othername"), "dNSName", List.of("domain.com"), "uniformResourceIdentifier",
                    List.of(), "directoryName", List.of());

    @Test
    void testSerializeSans() {
        String result = CertificateUtil.serializeSans(VALID_SAN_MAP);
        Assertions.assertEquals(VALID_SAN_STRING, result);

        String nullResult = CertificateUtil.serializeSans(null);
        Assertions.assertEquals("{}", nullResult);

        String emptyResult = CertificateUtil.serializeSans(new HashMap<>());
        Assertions.assertEquals("{}", emptyResult);
    }

    @Test
    void testDeserializeSans() {
        Map<String, List<String>> result = CertificateUtil.deserializeSans(VALID_SAN_STRING);
        Assertions.assertEquals(VALID_SAN_MAP, result);

        Map<String, List<String>> emptyResult = CertificateUtil.deserializeSans(null);
        Assertions.assertTrue(emptyResult.isEmpty());

        Map<String, List<String>> emptyStringResult = CertificateUtil.deserializeSans("");
        Assertions.assertTrue(emptyStringResult.isEmpty());
    }

    @Test
    void testInvalidDeserializeSans() {
        String invalidJson = "{invalid json}";
        Assertions.assertThrows(IllegalStateException.class, () -> CertificateUtil.deserializeSans(invalidJson));
    }

    @Test
    void testInvalidSerializeSans() {
        Map<String, List<String>> invalidMap = new HashMap<>();
        invalidMap.put("invalidKey", null);

        Assertions.assertThrows(IllegalStateException.class, () -> CertificateUtil.serializeSans(invalidMap));
    }

    @Test
    void testParseHybridCertificate() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, SignatureException, OperatorCreationException, CertificateException {
        X509Certificate certificate = CertificateTestUtil.createHybridCertificate();

        Certificate certificateEntity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(certificateEntity, certificate);
        Assertions.assertEquals("ML-DSA-44", certificateEntity.getAltSignatureAlgorithm());

    }

    @Test
    void testIsValidationEnabled() {
        Certificate certificate = new Certificate();
        certificate.setArchived(true);
        Assertions.assertFalse(CertificateUtil.isValidationEnabled(certificate, null));
    }

    @Test
    void testPrepareIssuedCertificate_noQcStatements() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithoutEku();
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertNull(entity.getQcCompliance(), "qcCompliance should be null when no QCStatements extension");
        Assertions.assertNull(entity.getQcSscd(), "qcSscd should be null when no QCStatements extension");
        Assertions.assertNull(entity.getQcType(), "qcType should be null when no QCStatements extension");
        Assertions
                .assertNull(entity.getQcCcLegislation(),
                        "qcCcLegislation should be null when no QCStatements extension");
    }

    @Test
    void testPrepareIssuedCertificate_noEku_extendedKeyUsageCriticalIsNull() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithoutEku();
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions
                .assertNull(entity.getExtendedKeyUsage(),
                        "extendedKeyUsage should be null when EKU extension is absent");
        Assertions
                .assertNull(entity.getExtendedKeyUsageCritical(),
                        "extendedKeyUsageCritical should be null when EKU extension is absent — criticality is not applicable");
    }

    @Test
    void testPrepareIssuedCertificate_criticalEku_extendedKeyUsageCriticalIsTrue() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithEku(true);
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions
                .assertNotNull(entity.getExtendedKeyUsage(),
                        "extendedKeyUsage should be set when EKU extension is present");
        Assertions
                .assertTrue(entity.getExtendedKeyUsageCritical(),
                        "extendedKeyUsageCritical should be true when EKU extension is marked critical");
    }

    @Test
    void testPrepareIssuedCertificate_nonCriticalEku_extendedKeyUsageCriticalIsFalse() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithEku(false);
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions
                .assertNotNull(entity.getExtendedKeyUsage(),
                        "extendedKeyUsage should be set when EKU extension is present");
        Assertions
                .assertFalse(entity.getExtendedKeyUsageCritical(),
                        "extendedKeyUsageCritical should be false when EKU extension is present but not marked critical");
    }

    @Test
    void testPrepareIssuedCertificate_qcComplianceOnly() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithQcStatements(true, false, null, null);
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertTrue(entity.getQcCompliance(), "qcCompliance should be true");
        Assertions.assertFalse(entity.getQcSscd(), "qcSscd should be false");
        Assertions.assertNull(entity.getQcType(), "qcType should be null");
        Assertions.assertNull(entity.getQcCcLegislation(), "qcCcLegislation should be null");
    }

    @Test
    void testPrepareIssuedCertificate_qcSscdOnly() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithQcStatements(false, true, null, null);
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertFalse(entity.getQcCompliance(), "qcCompliance should be false");
        Assertions.assertTrue(entity.getQcSscd(), "qcSscd should be true");
        Assertions.assertNull(entity.getQcType(), "qcType should be null");
        Assertions.assertNull(entity.getQcCcLegislation(), "qcCcLegislation should be null");
    }

    @Test
    void testPrepareIssuedCertificate_qcTypeAllValues() throws Exception {
        X509Certificate x509 = CertificateTestUtil
                .createCertificateWithQcStatements(false, false, List.of(QcType.ESIGN, QcType.ESEAL, QcType.WEB), null);
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertNotNull(entity.getQcType(), "qcType should not be null");
        List<String> types = MetaDefinitions.deserializeArrayString(entity.getQcType());
        Assertions.assertTrue(types.contains(QcType.ESIGN.name()), "ESIGN should be present");
        Assertions.assertTrue(types.contains(QcType.ESEAL.name()), "ESEAL should be present");
        Assertions.assertTrue(types.contains(QcType.WEB.name()), "WEB should be present");
    }

    @Test
    void testPrepareIssuedCertificate_qcCcLegislation() throws Exception {
        X509Certificate x509 = CertificateTestUtil
                .createCertificateWithQcStatements(false, false, null, List.of("DE", "FR"));
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertNotNull(entity.getQcCcLegislation(), "qcCcLegislation should not be null");
        List<String> countries = MetaDefinitions.deserializeArrayString(entity.getQcCcLegislation());
        Assertions.assertTrue(countries.contains("DE"), "DE should be present");
        Assertions.assertTrue(countries.contains("FR"), "FR should be present");
    }

    @Test
    void testPrepareIssuedCertificate_allQcStatements() throws Exception {
        X509Certificate x509 = CertificateTestUtil
                .createCertificateWithQcStatements(true, true, List.of(QcType.ESIGN), List.of("AT"));
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertTrue(entity.getQcCompliance(), "qcCompliance should be true");
        Assertions.assertTrue(entity.getQcSscd(), "qcSscd should be true");
        List<String> types = MetaDefinitions.deserializeArrayString(entity.getQcType());
        Assertions.assertEquals(List.of(QcType.ESIGN.name()), types, "qcType should contain ESIGN");
        List<String> countries = MetaDefinitions.deserializeArrayString(entity.getQcCcLegislation());
        Assertions.assertEquals(List.of("AT"), countries, "qcCcLegislation should contain AT");
    }

    @Test
    void stampIssuedFields_setsFieldsButNotState() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithoutEku();
        Certificate cert = new Certificate();
        cert.setState(CertificateState.PENDING_ISSUE);

        CertificateUtil.stampIssuedFields(cert, x509);

        assertEquals(CertificateState.PENDING_ISSUE, cert.getState(), "stampIssuedFields must not touch state");
        assertNotNull(cert.getSerialNumber());
        assertNotNull(cert.getNotAfter());
    }

    @Test
    void prepareIssuedCertificate_stillSetsIssued() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithoutEku();
        Certificate cert = new Certificate();

        CertificateUtil.prepareIssuedCertificate(cert, x509);

        assertEquals(CertificateState.ISSUED, cert.getState());
        assertNotNull(cert.getSerialNumber());
    }

    @Test
    void applyRegistrationSan_persistsOtherNameAsOidEqualsValue() {
        // The otherName serialized form must match the one written for issued certificates
        // (getSanValueString) — both go through the shared formatOtherNameSan.
        Certificate cert = new Certificate();
        GeneralNameEntry otherName = new GeneralNameEntry();
        otherName.setType(GeneralNameType.OTHER_NAME);
        otherName.setOtherNameOid("1.2.3.4");
        otherName.setValue("example othername");

        CertificateUtil.applyRegistrationSan(cert, List.of(otherName));

        Map<String, List<String>> sans = CertificateUtil.deserializeSans(cert.getSubjectAlternativeNames());
        assertEquals(List.of("1.2.3.4=example othername"), sans.get("otherName"));
    }

    @Test
    void applyRegistrationSan_rejectsEntryWithoutType() {
        // A type-less entry cannot be bucketed; it must surface as a controlled ValidationException
        // (not an NPE), and nothing may be persisted on the certificate.
        Certificate cert = new Certificate();
        GeneralNameEntry typeless = new GeneralNameEntry();
        typeless.setValue("device-9");

        assertThrows(ValidationException.class, () -> CertificateUtil.applyRegistrationSan(cert, List.of(typeless)));
        assertNull(cert.getSubjectAlternativeNames());
    }

    @Test
    void applyRegistrationSan_rejectsOtherNameWithoutOid() {
        // An OID-less otherName would serialize a literal "null=value" SAN; reject it as a controlled
        // ValidationException instead, and persist nothing on the certificate.
        Certificate cert = new Certificate();
        GeneralNameEntry otherName = new GeneralNameEntry();
        otherName.setType(GeneralNameType.OTHER_NAME);
        otherName.setValue("device-9");

        assertThrows(ValidationException.class, () -> CertificateUtil.applyRegistrationSan(cert, List.of(otherName)));
        assertNull(cert.getSubjectAlternativeNames());
    }

    @Test
    void prepareCertificateRequestEntityFromCsr_populatesIdentityFromCsr() throws Exception {
        CertificateRequestEntity entity = new CertificateRequestEntity();

        CertificateUtil.prepareCertificateRequestEntityFromCsr(entity, generatePkcs10("CN=csr-cn", "csr.example.com"));

        assertEquals("csr-cn", entity.getCommonName());
        assertEquals("CN=csr-cn", entity.getSubjectDn());
        assertEquals(KeyAlgorithm.RSA.getCode(), entity.getPublicKeyAlgorithm());
        Map<String, List<String>> sans = CertificateUtil.deserializeSans(entity.getSubjectAlternativeNames());
        assertEquals(List.of("csr.example.com"), sans.get("dNSName"));
    }

    @Test
    void prepareCertificateRequestEntityFromCsr_multiCnSubject_keepsLeadingCnOfRenderedSubjectDn() throws Exception {
        CertificateRequestEntity entity = new CertificateRequestEntity();

        CertificateUtil.prepareCertificateRequestEntityFromCsr(entity, generatePkcs10("CN=first,CN=last", null));

        // The rendered subjectDn reverses RDN order, so last-wins CN extraction keeps commonName
        // aligned with the leading CN of the persisted subjectDn.
        assertEquals("CN=last, CN=first", entity.getSubjectDn());
        assertEquals("last", entity.getCommonName());
    }

    @Test
    void prepareCertificateRequestEntityFromCsr_leavesCommonNameNullWhenSubjectHasNone() throws Exception {
        CertificateRequestEntity entity = new CertificateRequestEntity();

        CertificateUtil.prepareCertificateRequestEntityFromCsr(entity, generatePkcs10("O=Acme", null));

        assertNull(entity.getCommonName());
        assertEquals("O=Acme", entity.getSubjectDn());
    }

    @Test
    void prepareCertificateRequestEntityFromCsr_subjectlessCrmf_leavesSubjectColumnsNull() throws Exception {
        CertificateRequestEntity entity = new CertificateRequestEntity();

        CertificateUtil.prepareCertificateRequestEntityFromCsr(entity, generateSubjectlessCrmf());

        assertNull(entity.getSubjectDn());
        assertNull(entity.getCommonName());
        assertEquals(KeyAlgorithm.RSA.getCode(), entity.getPublicKeyAlgorithm());
    }

    @Test
    void prepareCertificateRequestEntityFromCsr_rejectsRequestWithoutPublicKey() throws Exception {
        CertificateRequest requestWithoutKey = mock(CertificateRequest.class);
        when(requestWithoutKey.getPublicKey()).thenReturn(null);
        CertificateRequestEntity entity = new CertificateRequestEntity();

        assertThrows(ValidationException.class,
                () -> CertificateUtil.prepareCertificateRequestEntityFromCsr(entity, requestWithoutKey));
    }

    @Test
    void getSanRendersCsrIpAddressAsOctetHex() throws Exception {
        // Grounds the matcher's IP canonicalization: a CSR IP SAN reads back as its octet hex, not the decoded
        // text a registration stores, so the two representations must be reconciled before comparison.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.iPAddress, "192.168.1.1")));
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=device-1"), keyPair.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        CertificateRequest request = new Pkcs10CertificateRequest(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())).getEncoded());

        List<String> ipSans = CertificateUtil.getSAN(request).get("iPAddress");

        Assertions.assertEquals(1, ipSans.size());
        Assertions
                .assertTrue(ipSans.get(0).equalsIgnoreCase("#c0a80101"),
                        "an IP SAN reads back from a CSR as its octet hex, was: " + ipSans.get(0));
    }

    private static CertificateRequest generatePkcs10(String subjectDn, String sanDnsName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                keyPair.getPublic());
        if (sanDnsName != null) {
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator
                    .addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(new GeneralName(GeneralName.dNSName, sanDnsName)));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }
        return new Pkcs10CertificateRequest(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())).getEncoded());
    }

    /** CRMF with a public key but no subject — CertTemplate.subject is OPTIONAL in RFC 4211. */
    private static CertificateRequest generateSubjectlessCrmf() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        CertificateRequestMessageBuilder builder = new CertificateRequestMessageBuilder(BigInteger.ONE)
                .setPublicKey(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);
        CertReqMessages messages = new CertReqMessages(builder.build().toASN1Structure());
        return new CrmfCertificateRequest(messages.getEncoded());
    }

    @Test
    void normalizeStoredSubjectDnNeutralizesRdnOrderAndAttributeNameCase() {
        assertEquals(CertificateUtil.normalizeStoredSubjectDn("CN=device-7, O=Acme"),
                CertificateUtil.normalizeStoredSubjectDn("o=Acme, cn=device-7"));
    }

    @Test
    void normalizeStoredSubjectDnPreservesAttributeValueCase() {
        assertNotEquals(CertificateUtil.normalizeStoredSubjectDn("CN=Device-7"),
                CertificateUtil.normalizeStoredSubjectDn("CN=device-7"));
    }

    @Test
    void absentSubjectNormalizesToTheEmptyString() {
        assertEquals("", CertificateUtil.normalizeSubjectDn(null));
        assertEquals("", CertificateUtil.normalizeStoredSubjectDn(null));
        assertEquals("", CertificateUtil.normalizeStoredSubjectDn("   "));
    }

    @Test
    void normalizeStoredSubjectDnRejectsAnUnparseableValue() {
        assertThrows(IllegalArgumentException.class, () -> CertificateUtil.normalizeStoredSubjectDn("not a dn"));
    }

    @Test
    void applyRegistrationSubjectPopulatesTheNormalizedSubject() {
        Certificate certificate = new Certificate();
        CertificateUtil.applyRegistrationSubject(certificate, "CN=device-7, O=Acme");
        assertEquals(CertificateUtil.normalizeStoredSubjectDn(certificate.getSubjectDn()),
                certificate.getSubjectDnNormalized());
    }

    @Test
    void applyRegistrationSubjectOfABlankDnStoresTheEmptyNormalizedSubject() {
        Certificate certificate = new Certificate();
        CertificateUtil.applyRegistrationSubject(certificate, " ");
        assertNull(certificate.getSubjectDn());
        assertEquals("", certificate.getSubjectDnNormalized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"PKCS12", "JKS", "JCEKS"})
    void parseUploadedCertificateContent_refusesAKeystoreStoredWithAPassword(String type) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        keyStore.store(file, "changeit".toCharArray());
        String content = Base64.getEncoder().encodeToString(file.toByteArray());

        ValidationException exception = assertThrows(ValidationException.class,
                () -> CertificateUtil.parseUploadedCertificateContent(content));
        assertEquals(KEYSTORE_REFUSAL_MESSAGE, exception.getMessage());
    }

    @Test
    void parseUploadedCertificateContent_refusesPkcs12WithoutMac() throws Exception {
        byte[] file = new PKCS12PfxPduBuilder().build(null, null).getEncoded();
        String content = Base64.getEncoder().encodeToString(file);

        ValidationException exception = assertThrows(ValidationException.class,
                () -> CertificateUtil.parseUploadedCertificateContent(content));
        assertEquals(KEYSTORE_REFUSAL_MESSAGE, exception.getMessage());
    }

    @Test
    void parseUploadedCertificateContent_uploadsPemCertificateAsBefore() throws Exception {
        X509Certificate certificate = CertificateTestUtil.createCertificateWithoutEku();
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(pem)) {
            pemWriter.writeObject(certificate);
        }
        String content = Base64.getEncoder().encodeToString(pem.toString().getBytes(StandardCharsets.US_ASCII));

        X509Certificate parsed = CertificateUtil.parseUploadedCertificateContent(content);

        Assertions.assertArrayEquals(certificate.getEncoded(), parsed.getEncoded());
    }

    @Test
    void parseUploadedCertificateContent_uploadsDerCertificateAsBefore() throws Exception {
        X509Certificate certificate = CertificateTestUtil.createCertificateWithoutEku();
        String content = Base64.getEncoder().encodeToString(certificate.getEncoded());

        X509Certificate parsed = CertificateUtil.parseUploadedCertificateContent(content);

        Assertions.assertArrayEquals(certificate.getEncoded(), parsed.getEncoded());
    }

    @Test
    void parseUploadedCertificateContent_uploadsPkcs7AsBefore() throws Exception {
        X509Certificate certificate = CertificateTestUtil.createCertificateWithoutEku();
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificate(new JcaX509CertificateHolder(certificate));
        byte[] pkcs7 = generator.generate(new CMSAbsentContent()).getEncoded();
        String content = Base64.getEncoder().encodeToString(pkcs7);

        X509Certificate parsed = CertificateUtil.parseUploadedCertificateContent(content);

        Assertions.assertArrayEquals(certificate.getEncoded(), parsed.getEncoded());
    }

}

package com.czertainly.core.util;

import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.certificate.QcType;
import com.czertainly.api.model.core.oid.OidCategory;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.oid.OidHandler;
import com.czertainly.core.util.MetaDefinitions;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    private static final String VALID_SAN_STRING = "{\"dNSName\":[\"czertainly.com\"],\"directoryName\":[],\"ediPartyName\":[],\"iPAddress\":[\"192.168.10.10\"],\"otherName\":[\"1.2.3.4=example othername\"],\"registeredID\":[],\"rfc822Name\":[],\"uniformResourceIdentifier\":[],\"x400Address\":[]}";

    private static final Map<String, List<String>> VALID_SAN_MAP = Map.of(
            "registeredID", List.of(),
            "ediPartyName", List.of(),
            "iPAddress", List.of("192.168.10.10"),
            "x400Address", List.of(),
            "rfc822Name", List.of(),
            "otherName", List.of("1.2.3.4=example othername"),
            "dNSName", List.of("czertainly.com"),
            "uniformResourceIdentifier", List.of(),
            "directoryName", List.of()
    );

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
    void testParseHybridCertificate() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, OperatorCreationException, CertificateException {
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
        Assertions.assertNull(entity.getQcCcLegislation(), "qcCcLegislation should be null when no QCStatements extension");
    }

    @Test
    void testPrepareIssuedCertificate_noEku_extendedKeyUsageCriticalIsNull() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithoutEku();
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertNull(entity.getExtendedKeyUsage(), "extendedKeyUsage should be null when EKU extension is absent");
        Assertions.assertNull(entity.getExtendedKeyUsageCritical(), "extendedKeyUsageCritical should be null when EKU extension is absent — criticality is not applicable");
    }

    @Test
    void testPrepareIssuedCertificate_criticalEku_extendedKeyUsageCriticalIsTrue() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithEku(true);
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertNotNull(entity.getExtendedKeyUsage(), "extendedKeyUsage should be set when EKU extension is present");
        Assertions.assertTrue(entity.getExtendedKeyUsageCritical(), "extendedKeyUsageCritical should be true when EKU extension is marked critical");
    }

    @Test
    void testPrepareIssuedCertificate_nonCriticalEku_extendedKeyUsageCriticalIsFalse() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithEku(false);
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertNotNull(entity.getExtendedKeyUsage(), "extendedKeyUsage should be set when EKU extension is present");
        Assertions.assertFalse(entity.getExtendedKeyUsageCritical(), "extendedKeyUsageCritical should be false when EKU extension is present but not marked critical");
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
        X509Certificate x509 = CertificateTestUtil.createCertificateWithQcStatements(
                false, false, List.of(QcType.ESIGN, QcType.ESEAL, QcType.WEB), null);
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
        X509Certificate x509 = CertificateTestUtil.createCertificateWithQcStatements(
                false, false, null, List.of("DE", "FR"));
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertNotNull(entity.getQcCcLegislation(), "qcCcLegislation should not be null");
        List<String> countries = MetaDefinitions.deserializeArrayString(entity.getQcCcLegislation());
        Assertions.assertTrue(countries.contains("DE"), "DE should be present");
        Assertions.assertTrue(countries.contains("FR"), "FR should be present");
    }

    @Test
    void testPrepareIssuedCertificate_allQcStatements() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithQcStatements(
                true, true, List.of(QcType.ESIGN), List.of("AT"));
        Certificate entity = new Certificate();
        CertificateUtil.prepareIssuedCertificate(entity, x509);
        Assertions.assertTrue(entity.getQcCompliance(), "qcCompliance should be true");
        Assertions.assertTrue(entity.getQcSscd(), "qcSscd should be true");
        List<String> types = MetaDefinitions.deserializeArrayString(entity.getQcType());
        Assertions.assertEquals(List.of(QcType.ESIGN.name()), types, "qcType should contain ESIGN");
        List<String> countries = MetaDefinitions.deserializeArrayString(entity.getQcCcLegislation());
        Assertions.assertEquals(List.of("AT"), countries, "qcCcLegislation should contain AT");
    }

    @ParameterizedTest
    @MethodSource("com.czertainly.core.util.CertificateTestData#provideCmpAcceptableTestData")
    void testIsCertificateCmpAcceptable(
            String testCaseName,
            List<CertificateTestData.KeyItemData> publicKeys,
            List<CertificateTestData.KeyItemData> privateKeys,
            CertificateState certificateState, CertificateValidationStatus validationStatus, boolean archived,
            boolean expectedResult
    ) {
        Certificate certificate = new Certificate();
        certificate.setState(certificateState);
        certificate.setValidationStatus(validationStatus);
        certificate.setArchived(archived);

        if (!publicKeys.isEmpty() || !privateKeys.isEmpty()) {
            CryptographicKey key = new CryptographicKey();
            Set<CryptographicKeyItem> items = new HashSet<>();
            for (CertificateTestData.KeyItemData keyData : publicKeys) {
                CryptographicKeyItem item = new CryptographicKeyItem();
                item.setType(keyData.type());
                item.setKeyAlgorithm(keyData.algorithm());
                item.setUsage(keyData.usage());
                item.setState(keyData.state());
                item.setKey(key);
                items.add(item);
            }
            for (CertificateTestData.KeyItemData keyData : privateKeys) {
                CryptographicKeyItem item = new CryptographicKeyItem();
                item.setType(keyData.type());
                item.setKeyAlgorithm(keyData.algorithm());
                item.setUsage(keyData.usage());
                item.setState(keyData.state());
                item.setKey(key);
                items.add(item);
            }
            key.setItems(items);
            certificate.setKey(key);
        }

        Assertions.assertEquals(expectedResult, CertificateUtil.isCertificateCmpAcceptable(certificate), "Test case '" + testCaseName + "' failed");
    }

    @ParameterizedTest
    @MethodSource("com.czertainly.core.util.CertificateTestData#provideScepCaCertificateTestData")
    void testIsCertificateScepCaCertAcceptable(
            String testCaseName,
            List<CertificateTestData.KeyItemData> publicKeys,
            List<CertificateTestData.KeyItemData> privateKeys,
            CertificateState certificateState, CertificateValidationStatus validationStatus, boolean archived,
            boolean intuneEnabled, boolean expectedResult
    ) {
        Certificate certificate = new Certificate();
        certificate.setState(certificateState);
        certificate.setValidationStatus(validationStatus);
        certificate.setArchived(archived);

        if (!publicKeys.isEmpty() || !privateKeys.isEmpty()) {
            CryptographicKey key = new CryptographicKey();
            Set<CryptographicKeyItem> items = new HashSet<>();
            for (CertificateTestData.KeyItemData keyData : publicKeys) {
                CryptographicKeyItem item = new CryptographicKeyItem();
                item.setType(keyData.type());
                item.setKeyAlgorithm(keyData.algorithm());
                item.setUsage(keyData.usage());
                item.setState(keyData.state());
                item.setKey(key);
                items.add(item);
            }
            for (CertificateTestData.KeyItemData keyData : privateKeys) {
                CryptographicKeyItem item = new CryptographicKeyItem();
                item.setType(keyData.type());
                item.setKeyAlgorithm(keyData.algorithm());
                item.setUsage(keyData.usage());
                item.setState(keyData.state());
                item.setKey(key);
                items.add(item);
            }
            key.setItems(items);
            certificate.setKey(key);
        }

        Assertions.assertEquals(expectedResult, CertificateUtil.isCertificateScepCaCertAcceptable(certificate, intuneEnabled), "Test case '" + testCaseName + "' failed");
    }

    @ParameterizedTest
    @MethodSource("com.czertainly.core.util.CertificateTestData#provideDigitalSigningAcceptableTestData")
    void testIsCertificateDigitalSigningAcceptable(
            String testCaseName,
            List<CertificateTestData.KeyItemData> publicKeys,
            List<CertificateTestData.KeyItemData> privateKeys,
            CertificateState certificateState, CertificateValidationStatus validationStatus, boolean archived,
            boolean withTokenProfile, List<String> extendedKeyUsages, boolean extendedKeyUsageCritical,
            SigningWorkflowType workflowType, boolean qualifiedTimestamp, Boolean qcCompliance,
            boolean expectedResult
    ) {
        Certificate certificate = new Certificate();
        certificate.setState(certificateState);
        certificate.setValidationStatus(validationStatus);
        certificate.setArchived(archived);

        if (!extendedKeyUsages.isEmpty()) {
            certificate.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(extendedKeyUsages));
        }
        certificate.setExtendedKeyUsageCritical(extendedKeyUsageCritical);
        if (qcCompliance != null) {
            certificate.setQcCompliance(qcCompliance);
        }

        if (!publicKeys.isEmpty() || !privateKeys.isEmpty()) {
            CryptographicKey key = new CryptographicKey();
            Set<CryptographicKeyItem> items = new HashSet<>();
            for (CertificateTestData.KeyItemData keyData : publicKeys) {
                CryptographicKeyItem item = new CryptographicKeyItem();
                item.setType(keyData.type());
                item.setKeyAlgorithm(keyData.algorithm());
                item.setUsage(keyData.usage());
                item.setState(keyData.state());
                item.setKey(key);
                items.add(item);
            }
            for (CertificateTestData.KeyItemData keyData : privateKeys) {
                CryptographicKeyItem item = new CryptographicKeyItem();
                item.setType(keyData.type());
                item.setKeyAlgorithm(keyData.algorithm());
                item.setUsage(keyData.usage());
                item.setState(keyData.state());
                item.setKey(key);
                items.add(item);
            }
            key.setItems(items);
            if (withTokenProfile) {
                key.setTokenProfile(new TokenProfile());
            }
            certificate.setKey(key);
        }

        Assertions.assertEquals(expectedResult, CertificateUtil.isCertificateDigitalSigningAcceptable(certificate, workflowType, qualifiedTimestamp), "Test case '" + testCaseName + "' failed");
    }
}

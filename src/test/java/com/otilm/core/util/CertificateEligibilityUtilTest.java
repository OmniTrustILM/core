package com.otilm.core.util;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.crypto.CryptographicKeyItemModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.oid.OidHandler;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

class CertificateEligibilityUtilTest {

    @BeforeAll
    static void initOidHandler() {
        // Seed the cache with an empty map so the class can be loaded outside a Spring context.
        for (OidCategory category : OidCategory.values()) {
            if (OidHandler.getOidCache(category) == null) {
                OidHandler.cacheOidCategory(category, new HashMap<>());
            }
        }
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

        Assertions.assertEquals(expectedResult, CertificateEligibilityUtil.isCertificateCmpAcceptable(certificate), "Test case '" + testCaseName + "' failed");
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

        Assertions.assertEquals(expectedResult, CertificateEligibilityUtil.isCertificateScepCaCertAcceptable(certificate, intuneEnabled), "Test case '" + testCaseName + "' failed");
    }

    @ParameterizedTest
    @MethodSource("com.czertainly.core.util.CertificateTestData#provideDigitalSigningAcceptableTestData")
    void testIsCertificateDigitalSigningAcceptable(
            String testCaseName,
            List<CertificateTestData.KeyItemData> publicKeys,
            List<CertificateTestData.KeyItemData> privateKeys,
            CertificateState certificateState, CertificateValidationStatus validationStatus, boolean archived,
            boolean withTokenProfile, boolean withTokenInstanceReference, List<String> extendedKeyUsages, boolean extendedKeyUsageCritical,
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
            if (withTokenInstanceReference) {
                key.setTokenInstanceReference(new TokenInstanceReference());
            }
            certificate.setKey(key);
        }

        Assertions.assertEquals(expectedResult, CertificateEligibilityUtil.isCertificateDigitalSigningAcceptable(certificate, workflowType, qualifiedTimestamp), "Test case '" + testCaseName + "' failed");
    }

    @ParameterizedTest
    @MethodSource("com.czertainly.core.util.CertificateTestData#provideDigitalSigningAcceptableTestData")
    void testIsCertificateDigitalSigningAcceptable_recordOverload(
            String testCaseName,
            List<CertificateTestData.KeyItemData> publicKeys,
            List<CertificateTestData.KeyItemData> privateKeys,
            CertificateState certificateState, CertificateValidationStatus validationStatus, boolean archived,
            boolean withTokenProfile, boolean withTokenInstanceReference, List<String> extendedKeyUsages, boolean extendedKeyUsageCritical,
            SigningWorkflowType workflowType, boolean qualifiedTimestamp, Boolean qcCompliance,
            boolean expectedResult
    ) {
        boolean hasKey = !publicKeys.isEmpty() || !privateKeys.isEmpty();

        List<CryptographicKeyItemModel> keyItems = new ArrayList<>();
        for (CertificateTestData.KeyItemData keyData : publicKeys) {
            keyItems.add(toKeyItemModel(keyData));
        }
        for (CertificateTestData.KeyItemData keyData : privateKeys) {
            keyItems.add(toKeyItemModel(keyData));
        }

        SigningCertificate certificate = new SigningCertificate(
                UUID.randomUUID(),
                "cn",
                archived,
                certificateState,
                validationStatus,
                List.copyOf(extendedKeyUsages),
                extendedKeyUsageCritical,
                qcCompliance,
                hasKey ? UUID.randomUUID() : null,
                (hasKey && withTokenProfile) ? UUID.randomUUID() : null,
                (hasKey && withTokenInstanceReference) ? UUID.randomUUID() : null,
                keyItems.stream().map(CryptographicKeyItemModel::keyItemUuid).toList()
        );

        Assertions.assertEquals(expectedResult,
                CertificateEligibilityUtil.isCertificateDigitalSigningAcceptable(certificate, keyItems, workflowType, qualifiedTimestamp),
                "Test case '" + testCaseName + "' failed");
    }

    private static CryptographicKeyItemModel toKeyItemModel(CertificateTestData.KeyItemData keyData) {
        return new CryptographicKeyItemModel(
                UUID.randomUUID(), true, keyData.algorithm(), keyData.state(), keyData.type(), keyData.usage(),
                null, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
    }
}

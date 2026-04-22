package com.czertainly.core.service.compliance;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.certificate.UploadCertificateRequestDto;
import com.czertainly.api.model.client.compliance.v2.ComplianceInternalRuleRequestDto;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.connector.secrets.SecretType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.compliance.ComplianceRuleStatus;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckRuleDto;
import com.czertainly.api.model.core.secret.SecretState;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.workflows.ConditionItemDto;
import com.czertainly.api.model.core.workflows.ConditionItemRequestDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.model.compliance.ComplianceResultDto;
import com.czertainly.core.model.compliance.ComplianceResultProviderRulesDto;
import com.czertainly.core.model.compliance.ComplianceResultRulesDto;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.ComplianceService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.KeyPair;
import java.time.OffsetDateTime;
import java.util.*;

class ComplianceServiceTest extends BaseComplianceTest {

    @Autowired
    private ComplianceService complianceService;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenRepository;

    @Autowired
    CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private SecretVersionRepository secretVersionRepository;

    @Autowired
    ClientOperationService clientOperationService;

    @Test
    void testCheckCompliance() throws Exception {
        var internalRuleAssoc = new ComplianceProfileRule();
        internalRuleAssoc.setComplianceProfile(complianceProfile);
        internalRuleAssoc.setComplianceProfileUuid(complianceProfile.getUuid());
        internalRuleAssoc.setResource(Resource.CERTIFICATE);
        internalRuleAssoc.setInternalRuleUuid(internalCertificateInvalidRuleUuid);
        complianceProfileRuleRepository.save(internalRuleAssoc);

        // add a V1 provider rule association to the seeded compliance profile
        var v1RuleAssoc = new ComplianceProfileRule();
        v1RuleAssoc.setComplianceProfile(complianceProfile);
        v1RuleAssoc.setComplianceProfileUuid(complianceProfile.getUuid());
        v1RuleAssoc.setResource(com.czertainly.api.model.core.auth.Resource.CERTIFICATE);
        v1RuleAssoc.setConnectorUuid(connectorV1.getUuid());
        v1RuleAssoc.setKind(KIND_V1);
        v1RuleAssoc.setComplianceRuleUuid(complianceV1RuleUuid);
        complianceProfileRuleRepository.save(v1RuleAssoc);

        var v2RuleAssoc = new ComplianceProfileRule();
        v2RuleAssoc.setComplianceProfile(complianceProfile);
        v2RuleAssoc.setComplianceProfileUuid(complianceProfile.getUuid());
        v2RuleAssoc.setResource(Resource.CRYPTOGRAPHIC_KEY);
        v2RuleAssoc.setConnectorUuid(connectorV2.getUuid());
        v2RuleAssoc.setKind(KIND_V2);
        v2RuleAssoc.setComplianceRuleUuid(complianceV2RuleKeyUuid);
        complianceProfileRuleRepository.save(v2RuleAssoc);

        var v2GroupAssoc = new ComplianceProfileRule();
        v2GroupAssoc.setComplianceProfile(complianceProfile);
        v2GroupAssoc.setComplianceProfileUuid(complianceProfile.getUuid());
        v2GroupAssoc.setResource(com.czertainly.api.model.core.auth.Resource.CERTIFICATE);
        v2GroupAssoc.setConnectorUuid(connectorV2.getUuid());
        v2GroupAssoc.setKind(KIND_V2);
        v2GroupAssoc.setComplianceGroupUuid(complianceV2Group2Uuid);
        complianceProfileRuleRepository.save(v2GroupAssoc);

        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/complianceProvider/%s/compliance".formatted(KIND_V2)))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "rules": [
                                    {
                                      "uuid": "%s",
                                      "name": "Rule1",
                                      "status": "nok"
                                    },
                                    {
                                      "uuid": "%s",
                                      "name": "Rule2",
                                      "status": "na"
                                    }
                                  ]
                                }
                                """.formatted(complianceV2RuleUuid, complianceV2Rule2Uuid)))
        );

        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v1/complianceProvider/%s/compliance".formatted(KIND_V1)))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "status": "nok",
                                  "rules": [
                                    {
                                      "uuid": "%s",
                                      "name": "Rule1-V1",
                                      "status": "na"
                                    }
                                  ]
                                }
                                """.formatted(complianceV1RuleUuid)))
        );

        // create and persist a certificate subject that belongs to the seeded RA profile
        var certificateChainInfo = CertificateGeneratorHelper.generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Test-Ca", "CN=Test-EndEntity", null);
        UploadCertificateRequestDto uploadRequestDto = new UploadCertificateRequestDto();
        uploadRequestDto.setCertificate(certificateChainInfo.getCaCertificateBase64Encoded());
        var certificateDto = certificateService.upload(uploadRequestDto, true);
        uploadRequestDto.setCertificate(certificateChainInfo.getEndEntityCertificateBase64Encoded());
        var certificate2Dto = certificateService.upload(uploadRequestDto, true);

        // run compliance check for the seeded profile (should include internal rules and both providers)
        List<SecuredUUID> uuids = List.of(SecuredUUID.fromUUID(complianceProfile.getUuid()));
        complianceService.checkCompliance(uuids, Resource.CERTIFICATE, null);

        // reload certificate and assert compliance result was stored
        Certificate certificate = certificateRepository.findByUuid(UUID.fromString(certificateDto.getUuid())).orElseThrow();
        ComplianceCheckResultDto complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, UUID.fromString(certificateDto.getUuid()));
        Assertions.assertEquals(ComplianceStatus.NOT_CHECKED, complianceCheckResult.getStatus(), "Compliance result status should be Not checked");
        Assertions.assertEquals(ComplianceStatus.NOT_CHECKED, certificate.getComplianceStatus(), "Compliance status should be Not checked");

        complianceService.checkResourceObjectCompliance(Resource.CERTIFICATE, UUID.fromString(certificate2Dto.getUuid()));
        Certificate certificate2 = certificateRepository.findByUuid(UUID.fromString(certificate2Dto.getUuid())).orElseThrow();
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, UUID.fromString(certificate2Dto.getUuid()));
        Assertions.assertEquals(ComplianceStatus.NOT_CHECKED, complianceCheckResult.getStatus(), "Compliance result status should be Not checked");
        Assertions.assertEquals(ComplianceStatus.NOT_CHECKED, certificate2.getComplianceStatus(), "Compliance status should be Not checked");

        ComplianceResultDto complianceResult = new ComplianceResultDto();
        complianceResult.setProviderRules(null);
        complianceResult.setInternalRules(null);
        complianceResult.setStatus(ComplianceStatus.NOT_CHECKED);
        complianceResult.setTimestamp(OffsetDateTime.now());
        certificate.setComplianceResult(complianceResult);
        certificate.setRaProfileUuid(associatedRaProfileUuid);
        certificateRepository.save(certificate);
        complianceService.checkCompliance(uuids, Resource.CERTIFICATE, null);

        // check failed compliance with invalid internal rule and V1 and V2 provider rules
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(ComplianceStatus.FAILED, complianceCheckResult.getStatus(), "Compliance result status should be Failed");
        Assertions.assertNotNull(complianceCheckResult.getMessage());

        complianceProfileRuleRepository.delete(internalRuleAssoc);

        complianceService.checkCompliance(uuids, Resource.CERTIFICATE, null);
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(ComplianceStatus.NOK, complianceCheckResult.getStatus(), "Compliance result status should be Not Compliant");

        certificate2.setRaProfileUuid(associatedRaProfileUuid);
        certificateRepository.save(certificate2);
        complianceService.checkResourceObjectCompliance(Resource.CERTIFICATE, certificate2.getUuid());
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, certificate2.getUuid());
        Assertions.assertEquals(ComplianceStatus.NOK, complianceCheckResult.getStatus(), "Compliance result status should be Not Compliant");
        certificate2Dto = certificateService.getCertificate(SecuredUUID.fromUUID(certificate2.getUuid()));
        // Expect 4 failed rules: 1 internal, 1 v1 provide0r rule, 2 v2 provider rules (one group with two rules)
        Assertions.assertEquals(3, certificate2Dto.getNonCompliantRules().size(), "There should be 3 non-compliant rules, internal skipped");
        Assertions.assertEquals(4, complianceCheckResult.getFailedRules().size(), "There should be 4 failed rules");

        complianceService.checkResourceObjectCompliance(Resource.RA_PROFILE, associatedRaProfileUuid);

        // check compliance of cryptographic key
        TokenInstanceReference token = new TokenInstanceReference();
        token.setName("Token");
        token.setAuthor("John Doe");
        token.setCreated(OffsetDateTime.now());
        token.setUpdated(OffsetDateTime.now());
        tokenRepository.save(token);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("Token Profile 1");
        tokenProfile.setTokenInstanceReferenceUuid(token.getUuid());
        tokenProfile.setAuthor("John Doe");
        tokenProfile.setCreated(OffsetDateTime.now());
        tokenProfile.setUpdated(OffsetDateTime.now());
        tokenProfileRepository.save(tokenProfile);

        ComplianceProfileAssociation complianceProfileAssociation = new ComplianceProfileAssociation();
        complianceProfileAssociation.setComplianceProfileUuid(complianceProfile.getUuid());
        complianceProfileAssociation.setResource(Resource.TOKEN_PROFILE);
        complianceProfileAssociation.setObjectUuid(tokenProfile.getUuid());
        complianceProfileAssociationRepository.save(complianceProfileAssociation);

        CryptographicKey key = cryptographicKeyRepository.findWithAssociationsByUuid(certificate.getKeyUuid()).orElseThrow();
        CryptographicKeyItem keyItem = key.getItems().iterator().next();
        key.setTokenProfileUuid(tokenProfile.getUuid());
        cryptographicKeyRepository.save(key);

        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/complianceProvider/%s/compliance".formatted(KIND_V2)))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "rules": []
                                }
                                """))
        );


        complianceService.checkCompliance(uuids, Resource.CRYPTOGRAPHIC_KEY, null);
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CRYPTOGRAPHIC_KEY_ITEM, keyItem.getUuid());
        Assertions.assertEquals(ComplianceStatus.NA, complianceCheckResult.getStatus(), "Compliance status should be Not applicable due to incompatible attributes setting");

        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(UUID.fromString("7ed00886-e706-11ec-8fea-0242ac120002"));
        requestAttribute.setName("KeyLength");
        requestAttribute.setContentType(AttributeContentType.INTEGER);
        requestAttribute.setContent(List.of(new IntegerAttributeContentV3(2048)));
        v2RuleAssoc.setAttributes(List.of(requestAttribute));
        complianceProfileRuleRepository.save(v2RuleAssoc);

        complianceService.checkResourceObjectCompliance(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CRYPTOGRAPHIC_KEY_ITEM, keyItem.getUuid());
        Assertions.assertEquals(ComplianceStatus.OK, complianceCheckResult.getStatus(), "Compliance status should be Compliant");

        complianceService.checkResourceObjectCompliance(Resource.CRYPTOGRAPHIC_KEY_ITEM, keyItem.getUuid());
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CRYPTOGRAPHIC_KEY_ITEM, keyItem.getUuid());
        Assertions.assertEquals(ComplianceStatus.OK, complianceCheckResult.getStatus(), "Compliance status should be Compliant");

        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/complianceProvider/%s/compliance".formatted(KIND_V2)))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "rules": [
                                    {
                                      "uuid": "%s",
                                      "name": "RuleKey",
                                      "status": "nok"
                                    }
                                  ]
                                }
                                """.formatted(complianceV2RuleKeyUuid)))
        );

        complianceService.checkResourceObjectCompliance(Resource.TOKEN_PROFILE, tokenProfile.getUuid());
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.CRYPTOGRAPHIC_KEY_ITEM, keyItem.getUuid());
        Assertions.assertEquals(ComplianceStatus.NOK, complianceCheckResult.getStatus(), "Compliance status should be Not Compliant");
    }

    @Test
    void testSecretCompliance() throws NotFoundException {
        // Check compliance for secret
        Secret secret = new Secret();
        secret.setName("secret");
        secret.setType(SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfileUuid(vaultProfileUuid);

        SecretVersion secretVersion = new SecretVersion();
        secretVersion.setVaultProfileUuid(vaultProfileUuid);
        secretVersion.setVersion(1);
        secretVersion.setFingerprint("fingerprint");
        secretVersionRepository.save(secretVersion);

        secret.setLatestVersion(secretVersion);
        secretRepository.save(secret);

        Assertions.assertDoesNotThrow(() -> complianceService.checkResourceObjectsComplianceValidation(Resource.VAULT_PROFILE, List.of(vaultProfileUuid)));
        Assertions.assertDoesNotThrow(() -> complianceService.checkResourceObjectsComplianceValidation(Resource.SECRET, List.of(secret.getUuid())));
        complianceService.checkResourceObjectCompliance(Resource.SECRET, secret.getUuid());
        ComplianceCheckResultDto complianceCheckResult = complianceService.getComplianceCheckResult(Resource.SECRET, secret.getUuid());
        Assertions.assertEquals(ComplianceStatus.OK, complianceCheckResult.getStatus());

        complianceService.checkCompliance(List.of(SecuredUUID.fromUUID(complianceProfile.getUuid())), Resource.SECRET, null);
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.SECRET, secret.getUuid());
        Assertions.assertEquals(ComplianceStatus.OK, complianceCheckResult.getStatus());
        OffsetDateTime lastUpdated = complianceCheckResult.getTimestamp();

        complianceService.checkResourceObjectCompliance(Resource.VAULT_PROFILE, vaultProfileUuid);
        complianceCheckResult = complianceService.getComplianceCheckResult(Resource.SECRET, secret.getUuid());
        Assertions.assertEquals(ComplianceStatus.OK, complianceCheckResult.getStatus());
        Assertions.assertNotEquals(lastUpdated, complianceCheckResult.getTimestamp());
    }

    @Test
    void testCertificateRequestComplianceCheckBeforeIssue() throws Exception {
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/v2/authorityProvider/authorities/1l/certificates/issue/attributes"))
                .willReturn(WireMock.aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[]").withStatus(200)));

        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/authorityProvider/authorities/1l/certificates/issue/attributes/validate"))
                .willReturn(WireMock.aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("true").withStatus(200)));

        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/authorityProvider/authorities/1l/certificates/issue"))
                .willReturn(WireMock.aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "certificateData": "TEST-DATA"
                                }
                                """).withStatus(200)));

        var internalRuleAssoc = new ComplianceProfileRule();
        internalRuleAssoc.setComplianceProfile(complianceProfile);
        internalRuleAssoc.setComplianceProfileUuid(complianceProfile.getUuid());
        internalRuleAssoc.setResource(Resource.CERTIFICATE_REQUEST);
        internalRuleAssoc.setInternalRuleUuid(internalCertificateRequestRuleUuid);
        complianceProfileRuleRepository.save(internalRuleAssoc);

        var certificateChainInfo = CertificateGeneratorHelper.generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Test-Ca-RSA", "CN=Test-EndEntity-RSA", null);
        UploadCertificateRequestDto uploadRequestDto = new UploadCertificateRequestDto();
        uploadRequestDto.setCertificate(certificateChainInfo.getEndEntityCertificateBase64Encoded());
        var certificateDto = certificateService.upload(uploadRequestDto, true);
        Certificate certWithRsaKey = certificateRepository.findByUuid(UUID.fromString(certificateDto.getUuid())).orElseThrow();
        certWithRsaKey.setRaProfileUuid(associatedRaProfileUuid);
        certificateRepository.save(certWithRsaKey);

        KeyPair certWithRsaKeyPair = certificateChainInfo.getEndEntityCertificateKeyPair();
        String csr = CertificateGeneratorHelper.generateCsrBase64Der(certWithRsaKeyPair.getPrivate(), certWithRsaKeyPair.getPublic(), "CN=Test-EndEntity-RSA", "SHA256WithRSA");
        ClientCertificateRenewRequestDto renewRequestDto = new ClientCertificateRenewRequestDto();
        renewRequestDto.setRequest(csr);
        var response = clientOperationService.renewCertificate(SecuredParentUUID.fromUUID(authorityUuid), SecuredUUID.fromUUID(associatedRaProfileUuid), certWithRsaKey.getUuid().toString(), renewRequestDto);

        Certificate renewedCert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REQUESTED, renewedCert.getState(), "Certificate should be in REQUESTED state");

        var internalRules = complianceProfileService.getComplianceRules(null, null, Resource.CERTIFICATE_REQUEST, null, null);
        ConditionItemDto conditionItemDto = internalRules.getFirst().getConditionItems().getFirst();

        ConditionItemRequestDto conditionItemRequestDto = new ConditionItemRequestDto();
        conditionItemRequestDto.setFieldSource(conditionItemDto.getFieldSource());
        conditionItemRequestDto.setFieldIdentifier(conditionItemDto.getFieldIdentifier());
        conditionItemRequestDto.setOperator(conditionItemDto.getOperator());
        conditionItemRequestDto.setValue(List.of("ECDSA"));

        ComplianceInternalRuleRequestDto requestDto = new ComplianceInternalRuleRequestDto();
        requestDto.setName("TestInternalRuleCertRequest");
        requestDto.setResource(Resource.CERTIFICATE_REQUEST);
        requestDto.setConditionItems(List.of(conditionItemRequestDto));
        complianceProfileService.updateComplianceInternalRule(internalCertificateRequestRuleUuid, requestDto);
        response = clientOperationService.renewCertificate(SecuredParentUUID.fromUUID(authorityUuid), SecuredUUID.fromUUID(associatedRaProfileUuid), certWithRsaKey.getUuid().toString(), renewRequestDto);
        renewedCert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REJECTED, renewedCert.getState(), "Certificate should be in REJECTED state");
    }

    @Test
    void testGetComplianceCheckResult_withInternalAndProviderRules() {
        // prepare compliance result with one failing internal rule and one failing provider rule (v2)
        ComplianceResultDto complianceResult = new ComplianceResultDto();
        complianceResult.setStatus(null);
        complianceResult.setTimestamp(null);

        ComplianceResultRulesDto internal = new ComplianceResultRulesDto();
        internal.setNotCompliant(new HashSet<>(List.of(internalCertificateRuleUuid)));
        internal.setNotApplicable(new HashSet<>());
        internal.setNotAvailable(new HashSet<>());
        complianceResult.setInternalRules(internal);

        ComplianceResultProviderRulesDto provider = new ComplianceResultProviderRulesDto();
        provider.setConnectorUuid(connectorV2.getUuid());
        provider.setKind(KIND_V2);
        provider.setNotCompliant(new HashSet<>(List.of(complianceV2RuleUuid)));
        provider.setNotApplicable(new HashSet<>());
        provider.setNotAvailable(new HashSet<>());
        complianceResult.setProviderRules(List.of(provider));

        // objectUuid only used for logging in implementation; use random
        UUID objectUuid = UUID.randomUUID();

        ComplianceCheckResultDto result = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, objectUuid, complianceResult);

        Assertions.assertNotNull(result);
        // Expect two failed rules: one internal and one provider
        Assertions.assertEquals(2, result.getFailedRules().size());
        Set<UUID> found = new HashSet<>();
        for (ComplianceCheckRuleDto dto : result.getFailedRules()) {
            found.add(dto.getUuid());
        }
        Assertions.assertTrue(found.contains(internalCertificateRuleUuid));
        Assertions.assertTrue(found.contains(complianceV2RuleUuid));
    }

    @Test
    void testGetComplianceCheckResult_statusMapping_NOK_NA_NOT_AVAILABLE() {
        ComplianceResultDto complianceResult = new ComplianceResultDto();

        ComplianceResultProviderRulesDto provider = new ComplianceResultProviderRulesDto();
        provider.setConnectorUuid(connectorV2.getUuid());
        provider.setKind(KIND_V2);

        // use three different provider rules (v2)
        UUID rNok = complianceV2RuleUuid;
        UUID rNa = complianceV2Rule2Uuid;
        UUID rNotAvailable = UUID.randomUUID(); // not present in provider responses -> mapped as NOT_AVAILABLE

        provider.setNotCompliant(new HashSet<>(List.of(rNok)));
        provider.setNotApplicable(new HashSet<>(List.of(rNa)));
        provider.setNotAvailable(new HashSet<>(List.of(rNotAvailable)));
        complianceResult.setProviderRules(List.of(provider));

        ComplianceCheckResultDto result = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, UUID.randomUUID(), complianceResult);

        Assertions.assertEquals(3, result.getFailedRules().size());

        Set<ComplianceRuleStatus> statuses = new HashSet<>();
        for (ComplianceCheckRuleDto dto : result.getFailedRules()) {
            statuses.add(dto.getStatus());
        }

        Assertions.assertTrue(statuses.contains(ComplianceRuleStatus.NOK));
        Assertions.assertTrue(statuses.contains(ComplianceRuleStatus.NA));
        Assertions.assertTrue(statuses.contains(ComplianceRuleStatus.NOT_AVAILABLE));
    }

    @Test
    void testMultipleProviders_resultsFromV1AndV2() {
        ComplianceResultDto complianceResult = new ComplianceResultDto();
        complianceResult.setProviderRules(null);
        complianceResult.setInternalRules(null);
        Assertions.assertDoesNotThrow(() -> complianceService.getComplianceCheckResult(Resource.CERTIFICATE, UUID.randomUUID(), complianceResult));

        ComplianceResultProviderRulesDto p1 = new ComplianceResultProviderRulesDto();
        p1.setConnectorUuid(connectorV1.getUuid());
        p1.setKind(KIND_V1);
        p1.setNotCompliant(new HashSet<>(List.of(complianceV1RuleUuid)));
        p1.setNotApplicable(new HashSet<>());
        p1.setNotAvailable(new HashSet<>());

        ComplianceResultProviderRulesDto p2 = new ComplianceResultProviderRulesDto();
        p2.setConnectorUuid(connectorV2.getUuid());
        p2.setKind(KIND_V2);
        p2.setNotCompliant(new HashSet<>(List.of(complianceV2RuleUuid)));
        p2.setNotApplicable(new HashSet<>());
        p2.setNotAvailable(new HashSet<>());

        complianceResult.setProviderRules(List.of(p1, p2));

        ComplianceCheckResultDto result = complianceService.getComplianceCheckResult(Resource.CERTIFICATE, UUID.randomUUID(), complianceResult);

        // Expect two provider rules present in failed rules
        Set<UUID> found = new HashSet<>();
        for (ComplianceCheckRuleDto dto : result.getFailedRules()) {
            found.add(dto.getUuid());
        }
        Assertions.assertTrue(found.contains(complianceV1RuleUuid));
        Assertions.assertTrue(found.contains(complianceV2RuleUuid));
    }

    // --- Regression tests for removeRulesFromComplianceResults ---

    /**
     * Helper: creates a certificate with pre-populated compliance_result JSONB and associates it
     * with the seeded compliance profile via the RA profile association.
     */
    private Certificate createCertificateWithComplianceResult(ComplianceResultDto complianceResult) throws Exception {
        var certChain = CertificateGeneratorHelper.generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Test-CA", "CN=Test-" + UUID.randomUUID(), null);
        UploadCertificateRequestDto uploadRequest = new UploadCertificateRequestDto();
        uploadRequest.setCertificate(certChain.getEndEntityCertificateBase64Encoded());
        var certDto = certificateService.upload(uploadRequest, true);
        Certificate cert = certificateRepository.findByUuid(UUID.fromString(certDto.getUuid())).orElseThrow();
        cert.setRaProfileUuid(associatedRaProfileUuid);
        cert.setComplianceResult(complianceResult);
        cert.setComplianceStatus(complianceResult != null ? complianceResult.getStatus() : ComplianceStatus.NOT_CHECKED);
        return certificateRepository.save(cert);
    }

    private ComplianceResultDto reloadComplianceResult(UUID certificateUuid) {
        return certificateRepository.findByUuid(certificateUuid).orElseThrow().getComplianceResult();
    }

    @Test
    void testRemoveInternalRuleFromComplianceResults() throws Exception {
        UUID ruleUuid = internalCertificateRuleUuid;
        UUID otherRuleUuid = internalCertificateRule2Uuid;

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultRulesDto internal = new ComplianceResultRulesDto();
        internal.setNotCompliant(new HashSet<>(Set.of(ruleUuid, otherRuleUuid)));
        internal.setNotApplicable(new HashSet<>());
        internal.setNotAvailable(new HashSet<>());
        result.setInternalRules(internal);
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, Set.of(ruleUuid), null, null);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        Assertions.assertNotNull(updated);
        Assertions.assertFalse(updated.getInternalRules().getNotCompliant().contains(ruleUuid), "Removed rule UUID should not be present");
        Assertions.assertTrue(updated.getInternalRules().getNotCompliant().contains(otherRuleUuid), "Other rule UUID should still be present");
    }

    @Test
    void testRemoveProviderRuleFromComplianceResults() throws Exception {
        UUID ruleUuid = complianceV2RuleUuid;
        UUID otherRuleUuid = complianceV2Rule2Uuid;

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultProviderRulesDto provider = new ComplianceResultProviderRulesDto();
        provider.setConnectorUuid(connectorV2.getUuid());
        provider.setKind(KIND_V2);
        provider.setNotCompliant(new HashSet<>(Set.of(ruleUuid)));
        provider.setNotApplicable(new HashSet<>(Set.of(otherRuleUuid)));
        provider.setNotAvailable(new HashSet<>());
        result.setProviderRules(new ArrayList<>(List.of(provider)));
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, Set.of(ruleUuid), connectorV2.getUuid(), KIND_V2);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        Assertions.assertNotNull(updated);
        ComplianceResultProviderRulesDto updatedProvider = updated.getProviderRules().stream()
                .filter(p -> p.getConnectorUuid().equals(connectorV2.getUuid()) && p.getKind().equals(KIND_V2))
                .findFirst().orElseThrow();
        Assertions.assertFalse(updatedProvider.getNotCompliant().contains(ruleUuid), "Removed rule UUID should not be present in notCompliant");
        Assertions.assertTrue(updatedProvider.getNotApplicable().contains(otherRuleUuid), "Other rule UUID should still be present in notApplicable");
    }

    @Test
    void testRemoveMultipleProviderRuleUuids() throws Exception {
        UUID rule1 = complianceV2RuleUuid;
        UUID rule2 = complianceV2Rule2Uuid;
        UUID rule3 = complianceV2RuleKeyUuid;

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultProviderRulesDto provider = new ComplianceResultProviderRulesDto();
        provider.setConnectorUuid(connectorV2.getUuid());
        provider.setKind(KIND_V2);
        provider.setNotCompliant(new HashSet<>(Set.of(rule1, rule2)));
        provider.setNotApplicable(new HashSet<>(Set.of(rule3)));
        provider.setNotAvailable(new HashSet<>());
        result.setProviderRules(new ArrayList<>(List.of(provider)));
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        // remove rule1 and rule3 in one call
        complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, Set.of(rule1, rule3), connectorV2.getUuid(), KIND_V2);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        ComplianceResultProviderRulesDto updatedProvider = updated.getProviderRules().stream()
                .filter(p -> p.getConnectorUuid().equals(connectorV2.getUuid()) && p.getKind().equals(KIND_V2))
                .findFirst().orElseThrow();
        Assertions.assertFalse(updatedProvider.getNotCompliant().contains(rule1), "rule1 should be removed from notCompliant");
        Assertions.assertTrue(updatedProvider.getNotCompliant().contains(rule2), "rule2 should remain in notCompliant");
        Assertions.assertFalse(updatedProvider.getNotApplicable().contains(rule3), "rule3 should be removed from notApplicable");
    }

    @Test
    void testRemoveGroupRules_emptyGroupRules_noChange() throws Exception {
        UUID ruleUuid = complianceV2RuleUuid;

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultProviderRulesDto provider = new ComplianceResultProviderRulesDto();
        provider.setConnectorUuid(connectorV2.getUuid());
        provider.setKind(KIND_V2);
        provider.setNotCompliant(new HashSet<>(Set.of(ruleUuid)));
        provider.setNotApplicable(new HashSet<>());
        provider.setNotAvailable(new HashSet<>());
        result.setProviderRules(new ArrayList<>(List.of(provider)));
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        // complianceV2GroupUuid is mocked to return empty rules list in BaseComplianceTest
        complianceService.removeGroupRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, complianceV2GroupUuid, connectorV2.getUuid(), KIND_V2);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        Assertions.assertNotNull(updated);
        Assertions.assertTrue(updated.getProviderRules().getFirst().getNotCompliant().contains(ruleUuid), "Rule should remain untouched when group has no rules");
    }

    @Test
    void testRemoveRules_nullComplianceResult_noError() throws Exception {
        Certificate cert = createCertificateWithComplianceResult(null);

        Assertions.assertDoesNotThrow(() ->
                complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, Set.of(UUID.randomUUID()), null, null));

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        Assertions.assertNull(updated, "NULL compliance_result should remain NULL");
    }

    @Test
    void testRemoveRules_ruleNotInResult_noChange() throws Exception {
        UUID presentRuleUuid = internalCertificateRuleUuid;
        UUID absentRuleUuid = UUID.randomUUID();

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultRulesDto internal = new ComplianceResultRulesDto();
        internal.setNotCompliant(new HashSet<>(Set.of(presentRuleUuid)));
        internal.setNotApplicable(new HashSet<>());
        internal.setNotAvailable(new HashSet<>());
        result.setInternalRules(internal);
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, Set.of(absentRuleUuid), null, null);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        Assertions.assertTrue(updated.getInternalRules().getNotCompliant().contains(presentRuleUuid), "Existing rule should remain when removing absent UUID");
    }

    @Test
    void testRemoveRules_emptySet_noOp() throws Exception {
        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultRulesDto internal = new ComplianceResultRulesDto();
        internal.setNotCompliant(new HashSet<>(Set.of(internalCertificateRuleUuid)));
        internal.setNotApplicable(new HashSet<>());
        internal.setNotAvailable(new HashSet<>());
        result.setInternalRules(internal);
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, Set.of(), null, null);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        Assertions.assertTrue(updated.getInternalRules().getNotCompliant().contains(internalCertificateRuleUuid), "Rule should remain when empty set is passed");
    }

    @Test
    void testRemoveMultipleInternalRuleUuids() throws Exception {
        UUID rule1 = internalCertificateRuleUuid;
        UUID rule2 = internalCertificateRule2Uuid;
        UUID rule3 = UUID.randomUUID();

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultRulesDto internal = new ComplianceResultRulesDto();
        internal.setNotCompliant(new HashSet<>(Set.of(rule1, rule3)));
        internal.setNotApplicable(new HashSet<>(Set.of(rule2)));
        internal.setNotAvailable(new HashSet<>());
        result.setInternalRules(internal);
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        // Remove rule1 and rule2 in one call
        complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, Set.of(rule1, rule2), null, null);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        Assertions.assertFalse(updated.getInternalRules().getNotCompliant().contains(rule1), "rule1 should be removed from notCompliant");
        Assertions.assertFalse(updated.getInternalRules().getNotApplicable().contains(rule2), "rule2 should be removed from notApplicable");
        Assertions.assertTrue(updated.getInternalRules().getNotCompliant().contains(rule3), "rule3 should remain in notCompliant");
    }

    @Test
    void testRemoveRulesFromSecretComplianceResults() throws Exception {
        UUID ruleUuid = internalSecretRuleUuid;

        Secret secret = new Secret();
        secret.setName("test-secret-" + UUID.randomUUID());
        secret.setType(SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfileUuid(vaultProfileUuid);

        SecretVersion secretVersion = new SecretVersion();
        secretVersion.setVaultInstanceUuid(vaultInstanceUuid);
        secretVersion.setVersion(1);
        secretVersion.setFingerprint("fp-" + UUID.randomUUID());
        secretVersionRepository.save(secretVersion);
        secret.setLatestVersion(secretVersion);

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultRulesDto internal = new ComplianceResultRulesDto();
        internal.setNotCompliant(new HashSet<>(Set.of(ruleUuid)));
        internal.setNotApplicable(new HashSet<>());
        internal.setNotAvailable(new HashSet<>());
        result.setInternalRules(internal);
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        secret.setComplianceResult(result);
        secret.setComplianceStatus(ComplianceStatus.NOK);
        secretRepository.save(secret);

        complianceService.removeRulesFromComplianceResults(complianceProfile.getUuid(), Resource.SECRET, Set.of(ruleUuid), null, null);

        Secret updatedSecret = secretRepository.findByUuid(secret.getUuid()).orElseThrow();
        Assertions.assertFalse(updatedSecret.getComplianceResult().getInternalRules().getNotCompliant().contains(ruleUuid), "Rule should be removed from secret compliance result");
    }

    @Test
    void testRemoveGroupRules_withRulesFromProvider() throws Exception {
        UUID groupRuleUuid = complianceV2RuleUuid;

        ComplianceResultDto result = new ComplianceResultDto();
        ComplianceResultProviderRulesDto provider = new ComplianceResultProviderRulesDto();
        provider.setConnectorUuid(connectorV2.getUuid());
        provider.setKind(KIND_V2);
        provider.setNotCompliant(new HashSet<>(Set.of(groupRuleUuid)));
        provider.setNotApplicable(new HashSet<>());
        provider.setNotAvailable(new HashSet<>());
        result.setProviderRules(new ArrayList<>(List.of(provider)));
        result.setStatus(ComplianceStatus.NOK);
        result.setTimestamp(OffsetDateTime.now());

        Certificate cert = createCertificateWithComplianceResult(result);

        // Override the batch POST stub to return the group with rules included
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/complianceProvider/%s/rules".formatted(KIND_V2)))
                .willReturn(WireMock.aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "rules": [],
                                  "groups": [
                                    {
                                      "uuid": "%s",
                                      "name": "Group2",
                                      "resource": "certificates",
                                      "rules": [
                                        {
                                          "uuid": "%s",
                                          "name": "Rule1",
                                          "resource": "certificates"
                                        }
                                      ]
                                    }
                                  ]
                                }
                                """.formatted(complianceV2Group2Uuid, groupRuleUuid))
                        .withStatus(200)));

        complianceService.removeGroupRulesFromComplianceResults(complianceProfile.getUuid(), Resource.CERTIFICATE, complianceV2Group2Uuid, connectorV2.getUuid(), KIND_V2);

        ComplianceResultDto updated = reloadComplianceResult(cert.getUuid());
        ComplianceResultProviderRulesDto updatedProvider = updated.getProviderRules().stream()
                .filter(p -> p.getConnectorUuid().equals(connectorV2.getUuid()) && p.getKind().equals(KIND_V2))
                .findFirst().orElseThrow();
        Assertions.assertFalse(updatedProvider.getNotCompliant().contains(groupRuleUuid), "Group rule UUID should be removed from compliance result");
    }

    @Test
    void testCheckComplianceValidation() {
        // check validation of compliance check request
        List<SecuredUUID> uuids = List.of(SecuredUUID.fromUUID(UUID.randomUUID()));
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkComplianceValidation(uuids, null, "SOME_TYPE"), "Resource must be specified");
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkCompliance(uuids, null, "SOME_TYPE"), "Resource must be specified");
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkComplianceValidation(uuids, Resource.NONE, "SOME_TYPE"), "Resource cannot be NONE, has to be compliance subject or has compliance profiles");
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkCompliance(uuids, Resource.NONE, "SOME_TYPE"), "Resource cannot be NONE, has to be compliance subject or has compliance profiles");
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkComplianceValidation(uuids, Resource.CERTIFICATE, "SOME_TYPE"), "Resource CERTIFICATE support only types from CertificateType enum");
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkCompliance(uuids, Resource.CERTIFICATE, "SOME_TYPE"), "Resource CERTIFICATE support only types from CertificateType enum");
        Assertions.assertThrows(NotFoundException.class, () -> complianceService.checkComplianceValidation(uuids, Resource.CERTIFICATE, CertificateType.X509.getCode()), "No compliance profile found with specified UUID");

        // check resource objects compliance validation
        List<UUID> objectUuids = List.of(UUID.randomUUID());
        UUID objectUuid = objectUuids.getFirst();
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkResourceObjectsComplianceValidation(Resource.NONE, objectUuids), "Resource cannot be NONE, has to be compliance subject or has compliance profiles");
        Assertions.assertThrows(ValidationException.class, () -> complianceService.checkResourceObjectCompliance(Resource.NONE, objectUuid), "Resource must be specified");
        Assertions.assertThrows(NotFoundException.class, () -> complianceService.checkResourceObjectsComplianceValidation(Resource.RA_PROFILE, objectUuids), "No RA Profile found with specified UUID");
    }
}

package com.czertainly.core.evaluator;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttributeV3;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.notification.NotificationProfileDetailDto;
import com.czertainly.api.model.client.notification.NotificationProfileRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.common.enums.BitMaskEnum;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateKeyUsage;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.enums.CertificateProtocol;
import com.czertainly.api.model.core.notification.RecipientType;
import com.czertainly.api.model.core.workflows.ExecutionType;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.workflows.TriggerType;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.entity.workflows.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.workflows.ActionRepository;
import com.czertainly.core.dao.repository.workflows.ExecutionItemRepository;
import com.czertainly.core.dao.repository.workflows.ExecutionRepository;
import com.czertainly.core.dao.repository.workflows.TriggerRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.service.*;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

class TriggerEvaluatorTest extends BaseSpringBootTest {

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10001");
    }

    @Autowired
    private TriggerEvaluator<CryptographicKeyItem> cryptographicKeyTriggerEvaluator;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private TriggerEvaluator<DiscoveryHistory> discoveryHistoryTriggerEvaluator;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private AttributeService attributeService;

    @Autowired
    private TriggerService triggerService;

    @Autowired
    private TriggerRepository triggerRepository;

    @Autowired
    private ActionRepository actionRepository;

    @Autowired
    private ExecutionRepository executionRepository;

    @Autowired
    private ExecutionItemRepository executionItemRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private CertificateTriggerEvaluator certificateTriggerEvaluator;

    @Autowired
    private NotificationProfileService notificationProfileService;

    @Autowired
    private ResourceObjectAssociationService associationService;

    @Autowired
    private LocationRepository locationRepository;

    @Autowired
    private CertificateLocationRepository certificateLocationRepository;
    @Autowired
    private ApprovalRepository approvalRepository;
    @Autowired
    private TriggerEvaluator<Approval> approvalTriggerEvaluator;


    private Certificate certificate;

    private ConditionItem condition;

    private Trigger trigger;
    private Action action;
    private Execution execution;
    private ExecutionItem executionItem;

    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        certificate = new Certificate();
        certificateRepository.save(certificate);

        condition = new ConditionItem();

        trigger = new Trigger();
        trigger.setName("TestTrigger");
        trigger.setResource(Resource.CERTIFICATE);

        execution = new Execution();
        execution.setName("TestExecution");
        execution.setResource(Resource.CERTIFICATE);
        execution.setType(ExecutionType.SET_FIELD);
        executionRepository.save(execution);

        executionItem = new ExecutionItem();
        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(FilterField.RA_PROFILE_NAME.toString());
        executionItem.setExecution(execution);
        execution.setItems(Set.of(executionItem));
        executionItemRepository.save(executionItem);

        action = new Action();
        action.setName("TestAction");
        action.setResource(Resource.CERTIFICATE);
        action.setExecutions(Set.of(execution));
        actionRepository.save(action);
        trigger.setActions(Set.of(action));
        trigger.setType(TriggerType.EVENT);
        trigger.setResource(Resource.CERTIFICATE);
        trigger = triggerRepository.save(trigger);
    }

    @Test
    void testCertificateRuleEvaluatorOnStringProperty() throws RuleException {
        certificate.setCommonName("Common Name");
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(FilterField.COMMON_NAME.toString());
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue("Common Name");
        condition.setOperator(FilterConditionOperator.EQUALS);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EQUALS);
        certificate.setCommonName("Common NameE");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.CONTAINS);
        condition.setValue("Name");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_CONTAINS);
        condition.setValue("abc");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.STARTS_WITH);
        condition.setValue("Comm");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.ENDS_WITH);
        condition.setValue("eE");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.MATCHES);
        condition.setValue("^\\\\d"); // starts with a number
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue("^(?:[^m]*m){3}[^m]*$"); // contains exactly 3 'm'
        condition.setOperator(FilterConditionOperator.NOT_MATCHES);
        condition.setValue("^\\\\d"); // starts with a number
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue("^(?:[^m]*m){3}[^m]*$"); // contains exactly 3 'm'
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        certificate.setCommonName(null);
        condition.setOperator(FilterConditionOperator.EMPTY);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertificateRuleEvaluatorOnKeyAlgorithmProperty() throws RuleException {
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        certificate.setPublicKeyAlgorithm("RSA");
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setFieldIdentifier(FilterField.PUBLIC_KEY_ALGORITHM.name());
        condition.setValue(List.of("RSA", "ML-DSA"));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EQUALS);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        // Not null String
        condition.setOperator(FilterConditionOperator.EMPTY);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        // Null String empty
        certificate.setPublicKeyAlgorithm(null);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertificateRuleEvaluatorOnEnumProperty() throws RuleException {
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setFieldIdentifier(FilterField.CERTIFICATE_VALIDATION_STATUS.name());
        condition.setValue(List.of(CertificateValidationStatus.VALID.getCode()));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EQUALS);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        // Not null validation status
        condition.setOperator(FilterConditionOperator.EMPTY);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        // Null validation status
        certificate.setValidationStatus(null);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertificateRuleEvaluatorOnBooleanProperty() throws RuleException {
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        certificate.setTrustedCa(true);
        condition.setFieldIdentifier(FilterField.TRUSTED_CA.toString());
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue(true);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertificateRuleEvaluatorOnListProperty() throws RuleException {
        Group group = new Group();
        group.setName("group");
        group = groupRepository.save(group);

        Group group2 = new Group();
        group2.setName("group2");
        group2 = groupRepository.save(group2);

        certificate.setGroups(new HashSet<>(List.of(group, group2)));
        certificate = certificateRepository.save(certificate);

        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setFieldIdentifier(FilterField.GROUP_NAME.toString());
        condition.setValue(List.of(group.getName(), group2.getName()));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EQUALS);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue(List.of("group3"));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setOperator(FilterConditionOperator.COUNT_EQUAL);
        condition.setValue(2);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue(1);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.COUNT_NOT_EQUAL);
        condition.setValue(1);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue(2);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.COUNT_GREATER_THAN);
        condition.setValue(1);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.COUNT_LESS_THAN);
        condition.setValue(5);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.EMPTY);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        certificate.setGroups(Set.of());
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        Location location = new Location();
        location.setName("loc");
        locationRepository.save(location);
        CertificateLocation certificateLocation = new CertificateLocation();
        certificateLocation.setLocation(location);
        certificateLocation.setCertificate(certificate);
        certificateLocationRepository.save(certificateLocation);
        certificate.setLocations(new HashSet<>(List.of(certificateLocation)));
        condition.setFieldIdentifier(FilterField.CERT_LOCATION_NAME.name());
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue(List.of("loc"));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.COUNT_EQUAL);
        condition.setValue(1);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertificateEvaluatorOnEnumListBitmask() throws RuleException {
        certificate.setKeyUsage(BitMaskEnum.convertSetToBitMask(EnumSet.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.KEY_ENCIPHERMENT, CertificateKeyUsage.KEY_AGREEMENT)));
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(FilterField.KEY_USAGE.name());
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.KEY_ENCIPHERMENT, CertificateKeyUsage.KEY_AGREEMENT));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.KEY_ENCIPHERMENT));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.KEY_ENCIPHERMENT, CertificateKeyUsage.KEY_CERT_SIGN));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue(List.of(CertificateKeyUsage.KEY_CERT_SIGN));
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.NOT_EQUALS);
        condition.setValue(List.of(CertificateKeyUsage.KEY_CERT_SIGN));
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setValue(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.KEY_ENCIPHERMENT));
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertificateRuleEvaluatorProtocols() throws RuleException {
        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setName("profile");
        CertificateProtocolAssociation protocolAssociation = new CertificateProtocolAssociation();
        protocolAssociation.setProtocol(CertificateProtocol.ACME);
        protocolAssociation.setAcmeProfile(acmeProfile);
        certificate.setProtocolAssociation(protocolAssociation);
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue(List.of(acmeProfile.getName()));
        condition.setFieldIdentifier(FilterField.ACME_PROFILE.name());
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertRuleEvaluatorRaProfile() throws RuleException {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("profile");
        certificate.setRaProfile(raProfile);
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue(List.of(raProfile.getName()));
        condition.setFieldIdentifier(FilterField.RA_PROFILE_NAME.name());
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }

    @Test
    void testExceptions() throws RuleException, ParseException {
        Rule rule = new Rule();
        rule.setResource(Resource.CRYPTOGRAPHIC_KEY);
        TriggerHistory triggerHistory = new TriggerHistory();
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateRules(triggerHistory, Set.of(rule), certificate));

        condition.setFieldIdentifier("invalid");
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        Assertions.assertThrows(RuleException.class, () -> certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setFieldIdentifier(FilterField.COMMON_NAME.toString());
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setOperator(FilterConditionOperator.GREATER);
        Assertions.assertThrows(RuleException.class, () -> certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setValue(123);
        condition.setOperator(FilterConditionOperator.CONTAINS);
        Assertions.assertThrows(RuleException.class, () -> certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setFieldIdentifier("expiryInDays");
        condition.setOperator(FilterConditionOperator.GREATER);
        condition.setValue(1);
        certificate.setNotAfter(new SimpleDateFormat(("dd.MM.yyyy")).parse("01.01.5000"));
        Assertions.assertThrows(RuleException.class, () -> certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
    }


    @Test
    void testEvaluatorDateTime() throws RuleException, ParseException {
        certificate.setNotBefore(new SimpleDateFormat(("yyyy-MM-dd HH:mm:ss")).parse("2019-12-01 22:10:15"));
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(FilterField.NOT_BEFORE.toString());
        condition.setValue("2019-12-01T22:10:00.274+00:00");
        condition.setOperator(FilterConditionOperator.GREATER);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setStartTime(new SimpleDateFormat(("yyyy-MM-dd HH:mm:ss")).parse("2019-12-01 22:10:15"));
        condition.setFieldIdentifier(FilterField.DISCOVERY_START_TIME.toString());
        condition.setValue("2019-12-01T22:10:00.274+00:00");
        Assertions.assertTrue(discoveryHistoryTriggerEvaluator.evaluateConditionItem(condition, discovery, Resource.DISCOVERY));
    }

    @Test
    void testEvaluatorDateInterval() throws RuleException {
        certificate.setNotAfter(convertToDateViaInstant(LocalDateTime.now().plusDays(10)));
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(FilterField.NOT_AFTER.toString());
        condition.setValue("P11D");
        condition.setOperator(FilterConditionOperator.IN_NEXT);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setValue("P5D");
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        certificate.setNotAfter(convertToDateViaInstant(LocalDateTime.now().minusDays(10)));
        condition.setOperator(FilterConditionOperator.IN_PAST);
        condition.setValue("P11D");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setValue("P5D");
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setValue("invalid");
        Assertions.assertThrows(RuleException.class, () -> certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        condition.setValue("P1D");
        condition.setOperator(FilterConditionOperator.IN_PAST);
        certificate.setNotAfter(convertToDateViaInstant(LocalDateTime.now().plusHours(1)));
        Assertions.assertFalse(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));
        condition.setOperator(FilterConditionOperator.IN_NEXT);
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE));

        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setStartTime(convertToDateViaInstant(LocalDateTime.now().minusDays(5).minusHours(3)));
        condition.setOperator(FilterConditionOperator.IN_PAST);
        condition.setFieldIdentifier(FilterField.DISCOVERY_START_TIME.toString());
        condition.setValue("P5DT4H");
        Assertions.assertTrue(discoveryHistoryTriggerEvaluator.evaluateConditionItem(condition, discovery, Resource.DISCOVERY));
        discovery.setStartTime(convertToDateViaInstant(LocalDateTime.now().plusDays(5).plusHours(3)));
        condition.setValue("P5DT4H");
        condition.setOperator(FilterConditionOperator.IN_NEXT);
        Assertions.assertTrue(discoveryHistoryTriggerEvaluator.evaluateConditionItem(condition, discovery, Resource.DISCOVERY));

    }

    private Date convertToDateViaInstant(LocalDateTime dateToConvert) {
        return java.util.Date
                .from(dateToConvert.atZone(ZoneId.systemDefault())
                        .toInstant());
    }

    @Test
    void testsCryptographicKeyRuleEvaluator() throws RuleException {
        CryptographicKeyItem cryptographicKey = new CryptographicKeyItem();
        cryptographicKey.setName("Key");
        ConditionItem newCondition = new ConditionItem();
        newCondition.setFieldSource(FilterFieldSource.PROPERTY);
        newCondition.setFieldIdentifier(FilterField.CKI_NAME.toString());
        newCondition.setOperator(FilterConditionOperator.NOT_EMPTY);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        cryptographicKey.setLength(256);
        newCondition.setFieldIdentifier(FilterField.CKI_LENGTH.toString());
        newCondition.setOperator(FilterConditionOperator.GREATER);
        newCondition.setValue(255);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue(255.4);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("255");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("255.4");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setOperator(FilterConditionOperator.EQUALS);
        newCondition.setValue(256);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue(256.4);
        Assertions.assertFalse(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("256");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("256.4");
        Assertions.assertFalse(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setOperator(FilterConditionOperator.NOT_EQUALS);
        newCondition.setValue(255);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue(255.4);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("255");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("255.4");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setOperator(FilterConditionOperator.GREATER_OR_EQUAL);
        newCondition.setValue(256);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue(255.4);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("256");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("255.4");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setOperator(FilterConditionOperator.LESSER_OR_EQUAL);
        newCondition.setValue(256);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue(257.4);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("256");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("257.4");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setOperator(FilterConditionOperator.LESSER);
        newCondition.setValue(256);
        Assertions.assertFalse(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue(257.4);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("257");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
        newCondition.setValue("257.4");
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));

    }

    @Test
    void testKeyCountCondition() throws RuleException {
        Group group = new Group();
        group.setName("group");
        group = groupRepository.save(group);

        Group group2 = new Group();
        group2.setName("group2");
        group2 = groupRepository.save(group2);

        CryptographicKey parentKey = new CryptographicKey();
        parentKey.setGroups(Set.of(group, group2));
        CryptographicKeyItem cryptographicKey = new CryptographicKeyItem();
        cryptographicKey.setName("Key");
        ConditionItem newCondition = new ConditionItem();
        newCondition.setFieldSource(FilterFieldSource.PROPERTY);
        cryptographicKey.setKey(parentKey);
        newCondition.setFieldIdentifier(FilterField.CK_GROUP.name());
        newCondition.setOperator(FilterConditionOperator.COUNT_EQUAL);
        newCondition.setValue(2);
        Assertions.assertTrue(cryptographicKeyTriggerEvaluator.evaluateConditionItem(newCondition, cryptographicKey, Resource.CRYPTOGRAPHIC_KEY));
    }

    @Test
    void testCertificateRuleEvaluatorCustomAttributes() throws AlreadyExistException, NotFoundException, RuleException, AttributeException {
        Certificate newCertificate = new Certificate();
        certificateRepository.save(newCertificate);

        CustomAttributeCreateRequestDto customAttributeRequest = new CustomAttributeCreateRequestDto();
        customAttributeRequest.setName("custom");
        customAttributeRequest.setLabel("custom");
        customAttributeRequest.setResources(List.of(Resource.CERTIFICATE));
        customAttributeRequest.setContentType(AttributeContentType.STRING);

        CustomAttributeDefinitionDetailDto customAttribute = attributeService.createCustomAttribute(customAttributeRequest);
        attributeEngine.updateObjectCustomAttributeContent(Resource.CERTIFICATE, newCertificate.getUuid(), null, customAttribute.getName(), List.of(new StringAttributeContentV3("ref", "data1"), new StringAttributeContentV3("ref", "data")));

        ConditionItem newCondition = new ConditionItem();
        newCondition.setFieldSource(FilterFieldSource.CUSTOM);
        newCondition.setFieldIdentifier("custom");
        newCondition.setOperator(FilterConditionOperator.EQUALS);
        newCondition.setValue("data");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(newCondition, newCertificate, Resource.CERTIFICATE));
    }

    @Test
    void testCertificateRuleEvaluatorMeta() throws RuleException, AttributeException {
        Certificate newCertificate = new Certificate();
        certificateRepository.save(newCertificate);
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);
        UUID connectorUuid = connector.getUuid();
        MetadataAttributeV2 metadataAttribute = new MetadataAttributeV2();
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setName("meta");
        metadataAttribute.setUuid(UUID.randomUUID().toString());
        metadataAttribute.setContent(List.of(new StringAttributeContentV2("ref", "data")));
        metadataAttribute.setType(AttributeType.META);

        MetadataAttributeProperties props = new MetadataAttributeProperties();
        props.setLabel("Test meta");
        metadataAttribute.setProperties(props);

        List<MetadataAttribute> content = new ArrayList<>();
        content.add(metadataAttribute);
        attributeEngine.updateMetadataAttributes(content, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, newCertificate.getUuid()).connector(connectorUuid).build());

        ConditionItem newCondition = new ConditionItem();
        newCondition.setFieldSource(FilterFieldSource.META);
        newCondition.setFieldIdentifier("meta|STRING");
        newCondition.setOperator(FilterConditionOperator.EQUALS);
        newCondition.setValue("data");
        Assertions.assertTrue(certificateTriggerEvaluator.evaluateConditionItem(newCondition, newCertificate, Resource.CERTIFICATE));
    }

    @Test
    void testSetCertificateGroup() throws RuleException {
        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(FilterField.GROUP_NAME.toString());
        Group group = new Group();
        group.setName("groupName");
        group = groupRepository.save(group);

        Group group2 = new Group();
        group2.setName("groupName2");
        group2 = groupRepository.save(group2);
        executionItem.setData(List.of(group.getUuid().toString(), group2.getUuid().toString()));
        certificateTriggerEvaluator.performActions(trigger, new TriggerHistory(), certificate, null);

        List<UUID> groupUuids = associationService.getGroupUuids(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(2, groupUuids.size());
        Assertions.assertTrue(groupUuids.contains(group.getUuid()));
        Assertions.assertTrue(groupUuids.contains(group2.getUuid()));
    }

    @Test
    void testSetCertificateOwner() throws RuleException {
        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(FilterField.OWNER.toString());
        executionItem.setData(UUID.randomUUID());

        mockServer = new WireMockServer(10001);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson("{ \"username\": \"ownerName\"}")
        ));

        certificateTriggerEvaluator.performActions(trigger, new TriggerHistory(), certificate, null);

        NameAndUuidDto owner = associationService.getOwner(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertNotNull(owner);
        Assertions.assertEquals("ownerName", owner.getName());

        mockServer.stop();
    }

    @Test
    void testSetRaProfile() throws RuleException, NotFoundException, CertificateException, IOException {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/identify"))
                .willReturn(WireMock.okJson("{\"meta\":[{\"version\": 2,\"uuid\":\"b42ab690-60fd-11ed-9b6a-0242ac120002\",\"name\":\"ejbcaUsername\",\"description\":\"EJBCA Username\",\"content\":[{\"version\": 2, \"reference\":\"ShO0lp7qbnE=\",\"data\":\"ShO0lp7qbnE=\"}],\"type\":\"meta\",\"contentType\":\"string\",\"properties\":{\"label\":\"EJBCA Username\",\"visible\":true,\"group\":null,\"global\":false}}]}")));

        Connector connector = new Connector();
        connector.setName("authorityInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReferenceRepository.save(authorityInstanceReference);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("Test RA profile");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("content");
        certificateContentRepository.save(certificateContent);
        certificate.setCertificateContent(certificateContent);
        certificateRepository.save(certificate);

        executionItem.setFieldSource(FilterFieldSource.PROPERTY);
        executionItem.setFieldIdentifier(FilterField.RA_PROFILE_NAME.toString());
        executionItem.setData(raProfile.getUuid());

        TriggerHistory triggerHistory = triggerService.createTriggerHistory(trigger.getUuid(), null, certificate.getUuid(), null, null, Resource.CERTIFICATE);
        certificateTriggerEvaluator.performActions(trigger, triggerHistory, certificate, null);

        CertificateDetailDto certificateDetailDto = certificateService.getCertificate(certificate.getSecuredUuid());
        Assertions.assertNotNull(certificate);
        Assertions.assertEquals(raProfile.getName(), certificateDetailDto.getRaProfile().getName());
        mockServer.stop();
    }

    @Test
    void testSetCustomAttribute() throws AlreadyExistException, AttributeException, RuleException {
        CustomAttributeCreateRequestDto createRequestDto = new CustomAttributeCreateRequestDto();
        createRequestDto.setName("custom");
        createRequestDto.setContentType(AttributeContentType.STRING);
        createRequestDto.setLabel("custom");
        createRequestDto.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        attributeService.createCustomAttribute(createRequestDto);
        LinkedHashMap<String, String> linkedHashSet = new LinkedHashMap<>();
        linkedHashSet.put("data", "data");
        linkedHashSet.put("reference", "ref");
        linkedHashSet.put("contentType", "string");
        executionItem.setFieldSource(FilterFieldSource.CUSTOM);
        executionItem.setFieldIdentifier("custom|STRING");
        executionItem.setData(List.of(linkedHashSet));
        certificateTriggerEvaluator.performActions(trigger, new TriggerHistory(), certificate, null);
        List<ResponseAttribute> responseAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertEquals(1, ((ResponseAttributeV3) responseAttributes.getFirst()).getContent().size());

        executionItem.setData(null);
        certificateTriggerEvaluator.performActions(trigger, new TriggerHistory(), certificate, null);
        responseAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertTrue(responseAttributes.isEmpty());

        executionItem.setData(List.of());
        certificateTriggerEvaluator.performActions(trigger, new TriggerHistory(), certificate, null);
        responseAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid());
        Assertions.assertTrue(responseAttributes.isEmpty());
    }

    @Test
    void testSendNotificationExecution() throws RuleException, NotFoundException, AlreadyExistException {
        NotificationProfileRequestDto requestDto = new NotificationProfileRequestDto();
        requestDto.setName("TestProfile");
        requestDto.setRecipientType(RecipientType.NONE);
        requestDto.setRepetitions(1);
        requestDto.setInternalNotification(true);
        NotificationProfileDetailDto notificationProfileDetailDto = notificationProfileService.createNotificationProfile(requestDto);

        execution.setType(ExecutionType.SEND_NOTIFICATION);
        executionRepository.save(execution);

        executionItem.setNotificationProfileUuid(UUID.fromString(notificationProfileDetailDto.getUuid()));
        executionItemRepository.save(executionItem);

        TriggerHistory triggerHistory = triggerService.createTriggerHistory(trigger.getUuid(), null, certificate.getUuid(), null, null, Resource.CERTIFICATE);
        certificateTriggerEvaluator.performActions(trigger, triggerHistory, certificate, null);
        Assertions.assertEquals(0, triggerHistory.getRecords().size());
    }

}

package com.otilm.core.integration.evaluator;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ConditionDto;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.otilm.api.model.core.workflows.EventStatus;
import com.otilm.api.model.core.workflows.RuleDetailDto;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.TriggerDetailDto;
import com.otilm.api.model.core.workflows.TriggerRequestDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.workflows.ConditionItem;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.cmp.CmpProfileRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.dao.repository.workflows.EventHistoryRepository;
import com.otilm.core.dao.repository.workflows.TriggerAssociationRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRecordRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.handlers.CertificateActionPerformedEventHandler;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.AcmeProfileExternalService;
import com.otilm.core.service.CmpProfileExternalService;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.ScepProfileExternalService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;

/**
 * Conditions on the profile of a protocol, evaluated on a certificate read from the database. A certificate has one
 * protocol association whose profile column serves every protocol, so a certificate issued through one protocol holds
 * no profile of another, and a certificate whose profile was deleted holds none; a condition on a profile that is not
 * there has to find it absent.
 */
class ProtocolProfileConditionITest extends BaseSpringBootTest {

    private static final List<CertificateProtocol> PROTOCOLS = List
            .of(CertificateProtocol.ACME, CertificateProtocol.SCEP, CertificateProtocol.CMP);

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateProtocolAssociationRepository protocolAssociationRepository;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private ScepProfileRepository scepProfileRepository;
    @Autowired
    private CmpProfileRepository cmpProfileRepository;
    @Autowired
    private AcmeProfileExternalService acmeProfileService;
    @Autowired
    private ScepProfileExternalService scepProfileService;
    @Autowired
    private CmpProfileExternalService cmpProfileService;
    @Autowired
    private CertificateTriggerEvaluator certificateTriggerEvaluator;
    @Autowired
    private CertificateActionPerformedEventHandler certificateActionPerformedEventHandler;
    @Autowired
    private RuleExternalService ruleService;
    @Autowired
    private TriggerExternalService triggerService;
    @Autowired
    private TriggerAssociationRepository triggerAssociationRepository;
    @Autowired
    private TriggerHistoryRepository triggerHistoryRepository;
    @Autowired
    private TriggerHistoryRecordRepository triggerHistoryRecordRepository;
    @Autowired
    private EventHistoryRepository eventHistoryRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;

    static Stream<Arguments> certificateProtocolAndOtherProtocol() {
        return PROTOCOLS
                .stream()
                .flatMap(issuedThrough -> PROTOCOLS
                        .stream()
                        .filter(other -> other != issuedThrough)
                        .map(other -> Arguments.of(issuedThrough, other)));
    }

    @ParameterizedTest
    @MethodSource("certificateProtocolAndOtherProtocol")
    void profileOfAnotherProtocolIsAbsent(CertificateProtocol issuedThrough, CertificateProtocol other) {
        UUID certificateUuid = certificateIssuedThrough(issuedThrough);
        FilterField otherProfile = profileField(other);

        inReadWriteTransaction(() -> {
            Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow();
            Assertions
                    .assertTrue(evaluate(certificate, otherProfile, FilterConditionOperator.EMPTY, null),
                            "a certificate issued through %s has no %s profile".formatted(issuedThrough, other));
            Assertions
                    .assertTrue(evaluate(certificate, otherProfile, FilterConditionOperator.NOT_EQUALS,
                            List.of(profileName(other))));
            Assertions
                    .assertFalse(evaluate(certificate, otherProfile, FilterConditionOperator.EQUALS,
                            List.of(profileName(other))));
        });
    }

    @ParameterizedTest
    @EnumSource(CertificateProtocol.class)
    void profileOfTheProtocolTheCertificateWasIssuedThroughIsRead(CertificateProtocol issuedThrough) {
        UUID certificateUuid = certificateIssuedThrough(issuedThrough);
        FilterField ownProfile = profileField(issuedThrough);

        inReadWriteTransaction(() -> {
            Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow();
            Assertions
                    .assertTrue(evaluate(certificate, ownProfile, FilterConditionOperator.EQUALS,
                            List.of(profileName(issuedThrough))));
            Assertions.assertFalse(evaluate(certificate, ownProfile, FilterConditionOperator.EMPTY, null));
        });
    }

    @ParameterizedTest
    @EnumSource(CertificateProtocol.class)
    void profileDeletedThroughTheServiceIsAbsent(CertificateProtocol issuedThrough) throws Exception {
        UUID profileUuid = saveProfile(issuedThrough);
        UUID certificateUuid = certificateIssuedThrough(issuedThrough, profileUuid);
        deleteProfile(issuedThrough, profileUuid);
        FilterField deletedProfile = profileField(issuedThrough);

        inReadWriteTransaction(() -> {
            Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow();
            Assertions
                    .assertTrue(evaluate(certificate, deletedProfile, FilterConditionOperator.EMPTY, null),
                            "the %s profile was deleted, so the certificate has none".formatted(issuedThrough));
            Assertions
                    .assertFalse(evaluate(certificate, deletedProfile, FilterConditionOperator.EQUALS,
                            List.of(profileName(issuedThrough))));
        });
    }

    @Test
    void triggerOnAnEmptyScepProfileMatchesACertificateIssuedThroughCmp() throws Exception {
        UUID certificateUuid = certificateIssuedThrough(CertificateProtocol.CMP);

        assertEmptyScepProfileTriggerMatches(certificateUuid);
    }

    @Test
    void triggerOnAnEmptyScepProfileMatchesACertificateOfADeletedScepProfile() throws Exception {
        UUID profileUuid = saveProfile(CertificateProtocol.SCEP);
        UUID certificateUuid = certificateIssuedThrough(CertificateProtocol.SCEP, profileUuid);
        deleteProfile(CertificateProtocol.SCEP, profileUuid);

        assertEmptyScepProfileTriggerMatches(certificateUuid);
    }

    private void assertEmptyScepProfileTriggerMatches(UUID certificateUuid) throws Exception {
        createIgnoreTriggerOnCertificateActions(FilterField.SCEP_PROFILE, FilterConditionOperator.EMPTY, null);

        Assertions
                .assertDoesNotThrow(() -> certificateActionPerformedEventHandler
                        .handleEvent(CertificateActionPerformedEventHandler
                                .constructEventMessage(certificateUuid, ResourceAction.REVOKE)));

        List<EventHistory> eventHistories = eventHistoryRepository.findAll();
        Assertions.assertEquals(1, eventHistories.size());
        Assertions.assertEquals(EventStatus.FINISHED, eventHistories.getFirst().getStatus());
        List<TriggerHistory> triggerHistories = triggerHistoryRepository.findAll();
        Assertions.assertEquals(1, triggerHistories.size());
        Assertions
                .assertTrue(triggerHistories.getFirst().isConditionsMatched(),
                        "the certificate has no SCEP profile, so its SCEP profile is empty");
        Assertions
                .assertTrue(triggerHistoryRecordRepository.findAll().isEmpty(),
                        "no condition was false or could not be evaluated");
    }

    private UUID certificateIssuedThrough(CertificateProtocol protocol) {
        return certificateIssuedThrough(protocol, saveProfile(protocol));
    }

    private UUID certificateIssuedThrough(CertificateProtocol protocol, UUID profileUuid) {
        Certificate certificate = certificateRepository.save(aCertificate().build());
        CertificateProtocolAssociation association = new CertificateProtocolAssociation();
        association.setCertificateUuid(certificate.getUuid());
        association.setProtocol(protocol);
        association.setProtocolProfileUuid(profileUuid);
        protocolAssociationRepository.save(association);
        return certificate.getUuid();
    }

    private void deleteProfile(CertificateProtocol protocol, UUID profileUuid) throws Exception {
        SecuredUUID uuid = SecuredUUID.fromUUID(profileUuid);
        switch (protocol) {
            case ACME -> acmeProfileService.deleteAcmeProfile(uuid);
            case SCEP -> scepProfileService.deleteScepProfile(uuid);
            case CMP -> cmpProfileService.deleteCmpProfile(uuid);
        }
    }

    private UUID saveProfile(CertificateProtocol protocol) {
        return switch (protocol) {
            case ACME -> {
                AcmeProfile profile = new AcmeProfile();
                profile.setName(profileName(protocol));
                yield acmeProfileRepository.save(profile).getUuid();
            }
            case SCEP -> {
                ScepProfile profile = new ScepProfile();
                profile.setName(profileName(protocol));
                yield scepProfileRepository.save(profile).getUuid();
            }
            case CMP -> {
                CmpProfile profile = new CmpProfile();
                profile.setName(profileName(protocol));
                profile.setEnabled(true);
                yield cmpProfileRepository.save(profile).getUuid();
            }
        };
    }

    private static String profileName(CertificateProtocol protocol) {
        return protocol.getCode().toLowerCase() + "-profile";
    }

    private static FilterField profileField(CertificateProtocol protocol) {
        return switch (protocol) {
            case ACME -> FilterField.ACME_PROFILE;
            case SCEP -> FilterField.SCEP_PROFILE;
            case CMP -> FilterField.CMP_PROFILE;
        };
    }

    private void inReadWriteTransaction(Runnable work) {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> work.run());
    }

    private boolean evaluate(Certificate certificate, FilterField field, FilterConditionOperator operator,
            Object value) {
        ConditionItem condition = new ConditionItem();
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(field.name());
        condition.setOperator(operator);
        condition.setValue(value);
        try {
            return certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE);
        } catch (RuleException e) {
            throw new AssertionError("%s %s could not be evaluated: %s".formatted(field, operator, e.getMessage()), e);
        }
    }

    private void createIgnoreTriggerOnCertificateActions(FilterField field, FilterConditionOperator operator,
            Object value) throws AlreadyExistException, NotFoundException {
        ConditionItemRequestDto conditionItemRequest = new ConditionItemRequestDto();
        conditionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequest.setFieldIdentifier(field.name());
        conditionItemRequest.setOperator(operator);
        conditionItemRequest.setValue(value);

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("ProfileCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItemRequest));
        ConditionDto condition = ruleService.createCondition(conditionRequest);

        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("ProfileRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        RuleDetailDto rule = ruleService.createRule(ruleRequest);

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("ProfileTrigger");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_ACTION_PERFORMED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setActionsUuids(List.of());
        triggerRequest.setIgnoreTrigger(true);
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        TriggerAssociation association = new TriggerAssociation();
        association.setTriggerUuid(UUID.fromString(trigger.getUuid()));
        association.setEvent(ResourceEvent.CERTIFICATE_ACTION_PERFORMED);
        association.setTriggeredBy(AuthHelper.getActingUserUuidOrNull());
        triggerAssociationRepository.save(association);
    }
}

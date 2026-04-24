package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.ResponseAttributeV3;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.czertainly.api.model.client.discovery.DiscoveryDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.discovery.DiscoveryCertificateDto;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.scheduler.*;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.api.model.scheduler.UpdateScheduledJob;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.workflows.TriggerAssociationRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.events.data.DiscoveryResult;
import com.czertainly.core.events.handlers.CertificateDiscoveredEventHandler;
import com.czertainly.core.events.handlers.DiscoveryFinishedEventHandler;
import com.czertainly.core.messaging.jms.listeners.EventListener;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.tasks.CbomSyncTask;
import com.czertainly.core.tasks.DiscoveryCertificateTask;
import com.czertainly.core.tasks.ScheduledJobInfo;
import com.czertainly.core.tasks.SystemScheduledJobs;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.UUID;

class SchedulerServiceTest extends BaseSpringBootTest {

    private static final int SCHEDULER_PORT = 8080;

    @Autowired
    private SchedulerService schedulerService;
    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;
    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;
    @Autowired
    private EventListener eventListener;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private RuleService ruleService;
    @Autowired
    private ActionService actionService;
    @Autowired
    private TriggerService triggerService;
    @Autowired
    private TriggerAssociationRepository triggerAssociationRepository;

    @Autowired
    private CertificateService certificateService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateEventHistoryRepository certificateEventHistoryRepository;

    @Autowired
    private DiscoveryService discoveryService;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryCertificateRepository discoveryCertificateRepository;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Test
    void runScheduledDiscoveryWithTriggers() throws AlreadyExistException, NotFoundException, AttributeException, SchedulerException, CertificateException, IOException, EventException {
        // register custom attribute
        CustomAttributeV3 certificateDomainAttr = new CustomAttributeV3();
        certificateDomainAttr.setUuid(UUID.randomUUID().toString());
        certificateDomainAttr.setName("domain");
        certificateDomainAttr.setType(AttributeType.CUSTOM);
        certificateDomainAttr.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties customProps = new CustomAttributeProperties();
        customProps.setLabel("Domain of certificate");
        certificateDomainAttr.setProperties(customProps);
        attributeEngine.updateCustomAttributeDefinition(certificateDomainAttr, List.of(Resource.CERTIFICATE));

        // create conditions
        ConditionItemRequestDto conditionItemRequest = new ConditionItemRequestDto();
        conditionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequest.setFieldIdentifier(FilterField.COMMON_NAME.name());
        conditionItemRequest.setOperator(FilterConditionOperator.ENDS_WITH);
        conditionItemRequest.setValue(".cz");

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("CommonNameEndsCZCondition");
        conditionRequest.setResource(Resource.CERTIFICATE);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItemRequest));
        ConditionDto condition = ruleService.createCondition(conditionRequest);

        // create ignore condition
        conditionItemRequest.setValue(".com");
        conditionRequest.setName("CommonNameEndsCOMCondition");
        ConditionDto conditionIgnore = ruleService.createCondition(conditionRequest);

        // create rule
        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("CommonNameEndsCZRule");
        ruleRequest.setResource(Resource.CERTIFICATE);
        ruleRequest.setConditionsUuids(List.of(condition.getUuid()));
        RuleDetailDto rule = ruleService.createRule(ruleRequest);

        // create ignore rule
        ruleRequest.setName("CommonNameEndsCOMRule");
        ruleRequest.setConditionsUuids(List.of(conditionIgnore.getUuid()));
        RuleDetailDto ruleIgnore = ruleService.createRule(ruleRequest);

        // create execution
        ExecutionItemRequestDto executionItemRequest = new ExecutionItemRequestDto();
        executionItemRequest.setFieldSource(FilterFieldSource.CUSTOM);
        executionItemRequest.setFieldIdentifier("%s|%s".formatted(certificateDomainAttr.getName(), certificateDomainAttr.getContentType().name()));
        executionItemRequest.setData("CZ");

        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("CategorizeCertificatesExecution");
        executionRequest.setResource(Resource.CERTIFICATE);
        executionRequest.setType(ExecutionType.SET_FIELD);
        executionRequest.setItems(List.of(executionItemRequest));
        ExecutionDto execution = actionService.createExecution(executionRequest);

        // create action
        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("CategorizeCertificatesAction");
        actionRequest.setResource(Resource.CERTIFICATE);
        actionRequest.setExecutionsUuids(List.of(execution.getUuid()));
        ActionDetailDto action = actionService.createAction(actionRequest);

        // create trigger
        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("DiscoveryCertificatesCategorization");
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        triggerRequest.setResource(Resource.CERTIFICATE);
        triggerRequest.setRulesUuids(List.of(rule.getUuid()));
        triggerRequest.setActionsUuids(List.of(action.getUuid()));
        TriggerDetailDto trigger = triggerService.createTrigger(triggerRequest);

        // create ignore trigger
        triggerRequest.setName("DiscoveryCertificatesCategorizationIgnore");
        triggerRequest.setRulesUuids(List.of(ruleIgnore.getUuid()));
        triggerRequest.setIgnoreTrigger(true);
        triggerRequest.setActionsUuids(List.of());
        TriggerDetailDto triggerIgnore = triggerService.createTrigger(triggerRequest);

        WireMockServer mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        // create connector
        Connector connector = new Connector();
        connector.setName("discoveryProviderConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.DISCOVERY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.DISCOVERY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("IpAndPort")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        // create scheduled discovery job
        String jobName = "TestScheduledDiscoveryWithTriggers";
        DiscoveryDto discoveryDto = new DiscoveryDto();
        discoveryDto.setName("TestCzertainlyDiscoveryWithTriggers");
        discoveryDto.setKind("IP-Hostname");
        discoveryDto.setConnectorUuid(connector.getUuid().toString());
        discoveryDto.setAttributes(List.of());
        discoveryDto.setTriggers(List.of(UUID.fromString(triggerIgnore.getUuid()), UUID.fromString(trigger.getUuid())));

        ScheduledJob scheduledJobEntity = new ScheduledJob();
        scheduledJobEntity.setJobName(jobName);
        scheduledJobEntity.setCronExpression("0 0/3 * * * ? *");
        scheduledJobEntity.setObjectData(discoveryDto);
        scheduledJobEntity.setEnabled(true);
        scheduledJobEntity.setJobClassName(DiscoveryCertificateTask.class.getName());

        scheduledJobEntity = scheduledJobsRepository.save(scheduledJobEntity);

        String discoveredCertificatesMockResponse = """
                {
                    "uuid": "4bd64640-be29-4e14-aad8-5c0ffa55c5bd",
                    "status": "completed",
                    "totalCertificatesDiscovered": 2,
                    "certificateData": [
                        {
                            "uuid": "0279d416-02ed-4415-a8cd-85af3f083222",
                            "base64Content": "MIIDyjCCArKgAwIBAgIUULw4BO/gvFzW2wMYXRhmz1kPPdAwDQYJKoZIhvcNAQELBQAwZDEUMBIGA1UEAwwLdGVzdGNlcnQuY3oxCzAJBgNVBAYTAkNaMRgwFgYDVQQIDA9DZW50cmFsIEJvaGVtaWExDzANBgNVBAcMBlNsYW7DvTEUMBIGA1UECgwLM0tleUNvbXBhbnkwHhcNMjQxMDIxMTAzMDEyWhcNMjUxMDIxMTAzMDEyWjBkMRQwEgYDVQQDDAt0ZXN0Y2VydC5jejELMAkGA1UEBhMCQ1oxGDAWBgNVBAgMD0NlbnRyYWwgQm9oZW1pYTEPMA0GA1UEBwwGU2xhbsO9MRQwEgYDVQQKDAszS2V5Q29tcGFueTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ112/a4p9sZ4F2fABLGtSBrbp71n/0uG+H/3usEQU8/FIW644ly5hNl8+SloPWryCCxOl+saXTKv62h0HnE/HNFMKlps4wwWNMsTploFKiAW9AbaDtzNrMy9f/orMoZldDZt5dLX8UR3qMmdK8nlqiJOyCAxIS70OsEQC8fGuIMNYeW6eidXGHjvpqApWnGTyA4U1bJWsDWcOIh/LL2ae9nwTJjVrHthrM6Wq6PplaPxEKYABp51UAQLMzY+cJElcKmwQxiK+zOHns7/ocosZVqI2QyxSmG60icabyrIT6HQHKVNzZHkltmduyYun9YZ+nl68YOuNmtSNi1TLMlfGECAwEAAaN0MHIwHQYDVR0OBBYEFOWFJRXdCer5Bpj+9JrquuJ7e5eQMB8GA1UdIwQYMBaAFOWFJRXdCer5Bpj+9JrquuJ7e5eQMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAA6AWaBFDAWL8oSBCP3q1s2Gq9QhR2QEBZ5tPOMTN5GpIzXxXdm4nHHBK/pSFABUNmrwQMapvq/y6IZ7hNMdC89MTOsHLD0EVPmHHO4xhzMG08XpJdevTrvktjpt0+ju81ratLg34pvJLeLF7ZL5AxwOl6qKX6RgwHpdBUipAYeeVhTVtQ7FLvakKDwYLiN6YFXuM1+CDAK3fsJ6sZki3uRvLYsUi7bguIQCmCQ0/n+T62Driq6mh1FkFB3sgpSFjfEo3bEaaHzF1YZr6otTYPNzcLCStJ5SYNBXKbw7YKAcYavL6yMNTQ2CjmLVnwjjd3O/Sv1kEhZMu86mHeNZK0I=",
                            "meta": []
                        },
                        {
                            "uuid": "ea119f0f-80fb-4d51-aa43-a049f9794a80",
                            "base64Content": "MIIDzDCCArSgAwIBAgIUZIyXNStxHEmQiOtuYAj7C7fJ9NQwDQYJKoZIhvcNAQELBQAwZTEVMBMGA1UEAwwMdGVzdGNlcnQuY29tMQswCQYDVQQGEwJDWjEYMBYGA1UECAwPQ2VudHJhbCBCb2hlbWlhMQ8wDQYDVQQHDAZTbGFuw70xFDASBgNVBAoMCzNLZXlDb21wYW55MB4XDTI0MTAyMTEwMzUwOFoXDTI1MTAyMTEwMzUwOFowZTEVMBMGA1UEAwwMdGVzdGNlcnQuY29tMQswCQYDVQQGEwJDWjEYMBYGA1UECAwPQ2VudHJhbCBCb2hlbWlhMQ8wDQYDVQQHDAZTbGFuw70xFDASBgNVBAoMCzNLZXlDb21wYW55MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2CDSXCL/6oE6jOHAxmPMwPSz11P4A4On0R2vo4ff6828lztprQZfdZFpDHiTMi8KRmZWCLtvbwO9inrIB0Ucs0psOuDOOuQdBe6PxmED2jG0NZFXk6N2oz4Ii8HjzDdvkNuPPDSPRrNoHZj4AGp00e5Eap5BXjEyWfp+Q/YO8Jxe96VFRtjZAV2u0/ooX1iu79E9Kuy59dyddGUTP0NCFML21VNp+G2LSRdDjlXPAjpftZ/f2l/1/6V55HI78R2fH801fEgwsPfB60k/LGX5O4f7erbZmTTUxCAq2LUZ4jjbJmuxqI9ExJkI0Oj5f1del6/216VVGZzB3OsaniatfQIDAQABo3QwcjAdBgNVHQ4EFgQUWLvLB6z1rgd0blgV8FPXHYXJQqgwHwYDVR0jBBgwFoAUWLvLB6z1rgd0blgV8FPXHYXJQqgwDgYDVR0PAQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEADYJZwsU1ucUOvq45aGZ4T9/4/H8Cy+HE761j+9CB6IV2ARnM5xG9CLSKRaDkzHwwbtREJljCcg1b8ZzjmGwjwBqvHDesWw87oz/6w2CdqEoILnUxkYoLLQ6wRtEKSUZEUzeEwqeVVcvo6TrsVz3dPkoeHubkEhhdaNyOjtbQs2F3JMrjhXsu2vXJ4D7ugFAsMx4w2LsxYLuAeG/njXseca80G+0f8NqFz+q4WpjxNdSY1Z4FrP2OGkVpSjFzJEWwMsdXSKB3QjaL1XW7QSjgefVXA+NPpgzXlFvxo+c4SnoCZ3QwcQIQ+QEEwCwA9Xvw96cFheLinFmLLsuobsNEHQ==",
                            "meta": []
                        },
                        {
                            "uuid": "dd601efe-0252-4b65-bd68-967201122dc8",
                            "base64Content": "MIIDZTCCAkygAwIBAgIBADANBgkqhkiG9w0BAQ0FADBMMQswCQYDVQQGEwJzazERMA8GA1UECAwIU2xvdmFraWExFDASBgNVBAoMC1Rlc3RDb21wYW55MRQwEgYDVQQDDAt0ZXN0Y2VydC5zazAeFw0yNTA1MDgxMjQ1MjZaFw0yNjA1MDgxMjQ1MjZaMEwxCzAJBgNVBAYTAnNrMREwDwYDVQQIDAhTbG92YWtpYTEUMBIGA1UECgwLVGVzdENvbXBhbnkxFDASBgNVBAMMC3Rlc3RjZXJ0LnNrMIIBIzANBgkqhkiG9w0BAQEFAAOCARAAMIIBCwKCAQIArQGMK3T2SgsCI+zxOkUK2FPAr/RArYb9PDn7SEa9j+HvQIMSIo3wHnI5X/jUwt113uy3QIyvvE4mLVc8IM+IPxXSrlGdrCMgjbPKsS+Byz1hixP7q5pMPl+GW7IlqCCV4HKxpVwIPOHc8kDKj45kZlG/kg1cjYjIcut0nMwE8yYkQJJt3fDmV+MMrGdFwTcpD+FMxwYLwtTfNXyjZmjbVjsztdP5UmVpnVMJEBQK3ghyev1jjN9loGuvebUIuYLPkN+ppZKpdZTMo+KTZI0G43GTK9nb4eAz9SATk4aea64yAIlO8CLkGOzCG+rhABSFQGJQNfqjqdg5N/+oUq9ETC8CAwEAAaNQME4wHQYDVR0OBBYEFEJImX9Y09Nf4y4RbodubMU8qb/NMB8GA1UdIwQYMBaAFEJImX9Y09Nf4y4RbodubMU8qb/NMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQENBQADggECAE+HNIPiaFGIwNrCxqkeRIlyNPfcG3sQPbcdFZyvGtmvRO62IoXq3YLRMQh9eMQ6fPyR/3Tf5EcQE/8RMiC1Of4hLeCHiptHYg3QslP0Cm15UGDTSg1A0ehG/KvINSfwxJr3r62MmaulgLE+1rvatyAsEDVkxdTGdKvsE8eTu8jS7KYaV27/rKmzDgB8VKbfkHBRUVEgsbbaUVdsM0vDVUMNZIn3voWnaq7zE+dwvSLds/95L/cGvhfEH6Vq5k5piBp3Nwpj8X0JABCmyk9ihbmecIhNeY/tWA/cr3sPwC+Gy2ezPbTO0siEEjAleD4DjP3NfGjfSNJnzOGcoBMRxUPN",
                            "meta": []
                        },
                        {
                            "uuid": "dd601efe-0252-4b65-bd68-967201122dc7",
                            "base64Content": "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",
                            "meta": []
                        }
                    ],
                    "meta": []
                }
                """;
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/discoveryProvider/[^/]+/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover"))
                .willReturn(WireMock.okJson(discoveredCertificatesMockResponse)));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/discoveryProvider/discover/4bd64640-be29-4e14-aad8-5c0ffa55c5bd"))
                .willReturn(WireMock.okJson(discoveredCertificatesMockResponse)));

        schedulerService.runScheduledJob(jobName);


        List<DiscoveryHistory> discoveries = discoveryRepository.findAll();
        Assertions.assertEquals(1, discoveries.size());

        // simulate events
        DiscoveryHistory discovery = discoveries.getFirst();
        EventMessage eventMessage = CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, new ScheduledJobInfo(scheduledJobEntity.getJobName(), scheduledJobEntity.getUuid(), scheduledJobHistoryRepository.findAll().getFirst().getUuid()));
        eventListener.processMessage(eventMessage);
        eventMessage = DiscoveryFinishedEventHandler.constructEventMessage(discovery.getUuid(), null, eventMessage.getScheduledJobInfo(), new DiscoveryResult(DiscoveryStatus.PROCESSING, null));
        eventListener.processMessage(eventMessage);

        discovery = discoveryRepository.findByUuid(discovery.getUuid()).orElseThrow();
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, discovery.getStatus());

        ScheduledJobHistory jobHistory = scheduledJobHistoryRepository.findTopByScheduledJobUuidOrderByJobExecutionDesc(scheduledJobEntity.getUuid());
        Assertions.assertNotNull(jobHistory);

        ScheduledJobHistoryResponseDto jobHistoryResponse = schedulerService.getScheduledJobHistory(SecurityFilter.create(), new PaginationRequestDto(), scheduledJobEntity.getUuid().toString());

        Assertions.assertEquals(1, jobHistoryResponse.getScheduledJobHistory().size());
        Assertions.assertEquals(SchedulerJobExecutionStatus.SUCCESS, jobHistoryResponse.getScheduledJobHistory().getFirst().getStatus());

        // assert triggers evaluation
        TriggerHistorySummaryDto triggerSummary = triggerService.getTriggerHistorySummary(discovery.getUuid().toString());
        Assertions.assertEquals(4, triggerSummary.getObjectsEvaluated());
        Assertions.assertEquals(2, triggerSummary.getObjectsMatched());
        Assertions.assertEquals(1, triggerSummary.getObjectsIgnored());

        DiscoveryCertificateResponseDto discoveredCertificates = discoveryService.getDiscoveryCertificates(discovery.getSecuredUuid(), null, 10, 1);
        Assertions.assertEquals(4, discoveredCertificates.getCertificates().size());

        boolean matched = false;
        boolean matchedHybrid = false;
        for (DiscoveryCertificateDto discoveryCertificate : discoveredCertificates.getCertificates()) {
            if (discoveryCertificate.getCommonName().endsWith(".cz")) {
                CertificateDetailDto certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromString(discoveryCertificate.getInventoryUuid()));

                matched = true;
                Assertions.assertEquals(1, certificateDetailDto.getCustomAttributes().size());
                Assertions.assertEquals("CZ", ((ResponseAttributeV3) certificateDetailDto.getCustomAttributes().getFirst()).getContent().getFirst().getData());
            }
            if (discoveryCertificate.getCommonName().contains("Hybrid")) {
                matchedHybrid = true;
                CertificateDetailDto certificateDetailDto = certificateService.getCertificate(SecuredUUID.fromString(discoveryCertificate.getInventoryUuid()));
                Assertions.assertNotNull(certificateDetailDto.getAltKey());
            }
        }
        Assertions.assertTrue(matched);
        Assertions.assertTrue(matchedHybrid);

        mockServer.stop();
    }

    @Test
    void testRegisterScheduledJobAndOperations() throws SchedulerException, NotFoundException {
        final String jobName = "TestDiscoveryScheduled";
        final String cronExpressionUpdate = "0 0/30 * * * ? *";

        WireMockServer mockServer = new WireMockServer(SCHEDULER_PORT);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/scheduler/create")).willReturn(
                WireMock.ok()));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/scheduler/update")).willReturn(
                WireMock.ok()));
        mockServer.stubFor(WireMock.delete(WireMock.urlPathMatching("/v1/scheduler/" + jobName)).willReturn(
                WireMock.noContent()));

        ScheduledJobDetailDto jobDetailDto = schedulerService.registerScheduledJob(DiscoveryCertificateTask.class,jobName, "0 0/3 * * * ? *", true, null);

        UpdateScheduledJob updateScheduledJob = new UpdateScheduledJob();
        updateScheduledJob.setCronExpression(cronExpressionUpdate);
        schedulerService.updateScheduledJob(jobDetailDto.getUuid().toString(), updateScheduledJob);

        jobDetailDto = schedulerService.getScheduledJobDetail(jobDetailDto.getUuid().toString());
        Assertions.assertEquals(jobName, jobDetailDto.getJobName());
        Assertions.assertEquals(cronExpressionUpdate, jobDetailDto.getCronExpression());

        schedulerService.deleteScheduledJob(jobDetailDto.getUuid().toString());

        ScheduledJobsResponseDto listResponse = schedulerService.listScheduledJobs(SecurityFilter.create(), new PaginationRequestDto());
        Assertions.assertEquals(0, listResponse.getTotalItems());

        mockServer.stop();
    }

    @Test
    void testSystemScheduledJobsRegistration() throws SchedulerException {
        WireMockServer mockServer = new WireMockServer(SCHEDULER_PORT);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        // 2. Stub the create endpoint
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/scheduler/create"))
                .willReturn(WireMock.ok()));

        try {
            SystemScheduledJobs systemScheduledJobs = new SystemScheduledJobs();
            systemScheduledJobs.setSchedulerService(schedulerService);

            systemScheduledJobs.registerJobs();

            // Verify all expected jobs are registered
            ScheduledJobsResponseDto jobs = schedulerService.listScheduledJobs(
                    SecurityFilter.create(), new PaginationRequestDto());

            Assertions.assertEquals(3, jobs.getScheduledJobs().size());

            List<String> jobClassNames = jobs.getScheduledJobs().stream()
                    .map(ScheduledJobDto::getJobName)
                    .toList();

            Assertions.assertTrue(jobClassNames.stream()
                    .anyMatch(name -> name.contains(CbomSyncTask.NAME)));
        } finally {
            // 3. Ensure server is stopped to free up the port
            mockServer.stop();
        }
    }

}

package com.czertainly.core.service;

import com.czertainly.api.model.client.signing.profile.SigningProfileRequestDto;
import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.signing.profile.scheme.DelegatedSigningRequestDto;
import com.czertainly.api.model.client.signing.profile.workflow.RawSigningWorkflowRequestDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class SigningProfileRecordPolicyTest extends BaseSpringBootTest {

    @Autowired
    private SigningProfileService service;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningProfileVersionRepository versionRepo;
    @Autowired
    private SigningRecordRepository recordRepo;
    @Autowired
    private ConnectorRepository connectorRepo;

    private Connector delegatedConnector;

    @BeforeEach
    void setUp() {
        Connector connector = new Connector();
        connector.setName("delegated-signer-connector");
        connector.setUrl("http://delegated-signer-connector");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        delegatedConnector = connectorRepo.save(connector);
    }

    private SigningProfileRequestDto buildRequest(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test");
        DelegatedSigningRequestDto scheme = new DelegatedSigningRequestDto();
        scheme.setConnectorUuid(delegatedConnector.getUuid());
        request.setSigningScheme(scheme);
        request.setWorkflow(new RawSigningWorkflowRequestDto());
        return request;
    }

    @Test
    void toggleChangeBumpsVersionWhenRecordsExist() throws Exception {
        // Create profile
        SigningProfileRequestDto createReq = buildRequest("toggle-test-" + System.nanoTime());
        var dto = service.createSigningProfile(createReq);
        UUID profileUuid = UUID.fromString(dto.getUuid());

        // Insert a signing record under version 1
        var profile = profileRepo.findById(profileUuid).orElseThrow();
        versionRepo.findBySigningProfileUuidAndVersion(profileUuid, 1).orElseThrow();
        SigningRecord rec = new SigningRecord();
        rec.setSigningProfile(profile);
        rec.setSigningProfileVersion(1);
        rec.setSigningTime(Instant.now());
        recordRepo.saveAndFlush(rec);

        // Update with recordSignature=true
        SigningProfileRequestDto updateReq = buildRequest(profile.getName());
        SigningRecordPolicyRequestDto policy = new SigningRecordPolicyRequestDto();
        policy.setRecordSignature(true);
        updateReq.setRecordPolicy(policy);
        service.updateSigningProfile(SecuredUUID.fromUUID(profileUuid), updateReq);

        profile = profileRepo.findById(profileUuid).orElseThrow();
        assertEquals(2, profile.getLatestVersion());

        var v2 = versionRepo.findBySigningProfileUuidAndVersion(profileUuid, 2).orElseThrow();
        assertTrue(v2.isRecordSignature());

        var v1Again = versionRepo.findBySigningProfileUuidAndVersion(profileUuid, 1).orElseThrow();
        assertFalse(v1Again.isRecordSignature());
    }

    @Test
    void operationalFieldsArePersistedWithoutBumpWhenNoRecordsExist() throws Exception {
        SigningProfileRequestDto createReq = buildRequest("operational-test-" + System.nanoTime());
        var dto = service.createSigningProfile(createReq);
        UUID profileUuid = UUID.fromString(dto.getUuid());

        // No signing records are inserted — operational-only change should not bump version
        var profile = profileRepo.findById(profileUuid).orElseThrow();

        // Update with retentionDays=14 only (no toggle changes, no records)
        SigningProfileRequestDto updateReq = buildRequest(profile.getName());
        SigningRecordPolicyRequestDto policy = new SigningRecordPolicyRequestDto();
        policy.setRetentionDays(14);
        updateReq.setRecordPolicy(policy);
        service.updateSigningProfile(SecuredUUID.fromUUID(profileUuid), updateReq);

        profile = profileRepo.findById(profileUuid).orElseThrow();
        // No records and no toggle change — version must not bump
        assertEquals(1, profile.getLatestVersion());
        // Operational field must be persisted on the profile header
        assertEquals(14, profile.getRetentionDays());
    }

    @Test
    void toggleAndOperationalChangeProducesOneNewVersion() throws Exception {
        SigningProfileRequestDto createReq = buildRequest("combined-test-" + System.nanoTime());
        var dto = service.createSigningProfile(createReq);
        UUID profileUuid = UUID.fromString(dto.getUuid());

        // Insert a record under version 1
        var profile = profileRepo.findById(profileUuid).orElseThrow();
        SigningRecord rec = new SigningRecord();
        rec.setSigningProfile(profile);
        rec.setSigningProfileVersion(1);
        rec.setSigningTime(Instant.now());
        recordRepo.saveAndFlush(rec);

        // Update with recordDtbs=true AND deleteAfterRetrieval=true
        SigningProfileRequestDto updateReq = buildRequest(profile.getName());
        SigningRecordPolicyRequestDto policy = new SigningRecordPolicyRequestDto();
        policy.setRecordDtbs(true);
        policy.setDeleteAfterRetrieval(true);
        updateReq.setRecordPolicy(policy);
        service.updateSigningProfile(SecuredUUID.fromUUID(profileUuid), updateReq);

        profile = profileRepo.findById(profileUuid).orElseThrow();
        assertEquals(2, profile.getLatestVersion());
        assertTrue(profile.isDeleteAfterRetrieval());

        var v2 = versionRepo.findBySigningProfileUuidAndVersion(profileUuid, 2).orElseThrow();
        assertTrue(v2.isRecordDtbs());

        long versionCount = versionRepo.findAll().stream()
                .filter(v -> v.getSigningProfileUuid().equals(profileUuid))
                .count();
        assertEquals(2, versionCount);
    }
}

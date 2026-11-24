package com.otilm.core.util.seeders;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateLocation;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.CertificateRenewalLocation;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.workflows.Action;
import com.otilm.core.dao.entity.workflows.Execution;
import com.otilm.core.dao.entity.workflows.ExecutionItem;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.workflows.ActionRepository;
import com.otilm.core.dao.repository.workflows.ExecutionItemRepository;
import com.otilm.core.dao.repository.workflows.ExecutionRepository;
import com.otilm.core.dao.repository.workflows.TriggerAssociationRepository;
import com.otilm.core.dao.repository.workflows.TriggerRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.CertificateBuilder;
import com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;

/**
 * Seeds what automatic renewal acts on: an RA profile with automatic renewal on or off, an issued certificate whose
 * renewal window started a day ago and whose renewal time has passed, optionally with a key and request the platform
 * holds, and a trigger whose only action renews the certificate.
 */
@Component
public class AutoRenewalSeeder {

    private static final Duration VALIDITY_LEFT = Duration.ofDays(30);

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRequestRepository certificateRequestRepository;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CryptographicKeySeeder keySeeder;
    @Autowired
    private RenewalWindowWriter renewalWindowWriter;
    @Autowired
    private ExecutionRepository executionRepository;
    @Autowired
    private ExecutionItemRepository executionItemRepository;
    @Autowired
    private ActionRepository actionRepository;
    @Autowired
    private TriggerRepository triggerRepository;
    @Autowired
    private TriggerAssociationRepository triggerAssociationRepository;
    @Autowired
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    @Autowired
    private LocationRepository locationRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private CertificateLocationRepository certificateLocationRepository;
    @Autowired
    private CertificateRenewalLocationRepository renewalLocationRepository;

    public RaProfile seedRaProfile(boolean autoRenewalEnabled) {
        RaProfile raProfile = AuthorityFixtures.v3Authority(authorityRepos()).raProfile();
        raProfile.setAutoRenewalEnabled(autoRenewalEnabled);
        return raProfileRepository.save(raProfile);
    }

    /** An RA profile with automatic renewal on, whose authority connector answers at the given server. */
    public RaProfile seedRaProfile(WireMockServer authority) {
        RaProfile raProfile = AuthorityFixtures.v2Authority(authorityRepos(), authority, null).raProfile();
        raProfile.setAutoRenewalEnabled(true);
        return raProfileRepository.save(raProfile);
    }

    /** A due certificate that neither a location nor the platform can re-key. */
    public Certificate seedDueCertificate(RaProfile raProfile) {
        Certificate certificate = certificateRepository.save(issuedCertificate(raProfile).build());
        makeDue(certificate.getUuid());
        return certificate;
    }

    /** A due certificate whose active private key and request the platform holds. */
    public Certificate seedDueHeldKeyCertificate(RaProfile raProfile) {
        CryptographicKey key = keySeeder
                .seedKey("auto-renewal-" + UUID.randomUUID(), null, null,
                        KeyItemSpec.signingPrivateKey(KeyAlgorithm.RSA));
        CertificateRequestEntity request = certificateRequestRepository
                .save(aCertificateRequest().withContent("cmVxdWVzdA==").withKeyUuid(key.getUuid()).build());
        Certificate certificate = certificateRepository
                .save(issuedCertificate(raProfile)
                        .withKeyUuid(key.getUuid())
                        .withCertificateRequestUuid(request.getUuid())
                        .build());
        makeDue(certificate.getUuid());
        return certificate;
    }

    /** A certificate in the given state, as the successor an automatic renewal started. */
    public Certificate seedSuccessor(RaProfile raProfile, CertificateState state) {
        return certificateRepository.save(issuedCertificate(raProfile).withState(state).build());
    }

    /**
     * A successor whose renewal Core has requested: it holds a request to issue, and a pending relation names the
     * certificate it renews.
     */
    public Certificate seedRequestedSuccessor(Certificate predecessor) {
        CertificateRequestEntity request = certificateRequestRepository
                .save(aCertificateRequest().withContent("cmVxdWVzdA==").build());
        Certificate successor = certificateRepository
                .save(issuedCertificate(predecessor.getRaProfile())
                        .withState(CertificateState.REQUESTED)
                        .withCertificateRequestUuid(request.getUuid())
                        .build());
        seedRelation(predecessor, successor, CertificateRelationType.PENDING);
        return successor;
    }

    /**
     * Push-only locations of one entity whose connector answers at the given server, each holding the certificate
     * without push attributes.
     */
    public List<Location> seedPushOnlyLocations(WireMockServer entityProvider, Certificate certificate,
            String... names) {
        EntityInstanceReference entity = seedEntity(LoopbackWireMock.url(entityProvider));
        return Stream.of(names).map(name -> {
            Location location = newLocation(entity, name);
            location.getCertificates().add(entry(certificate, location, List.of()));
            return locationRepository.save(location);
        }).toList();
    }

    /** A location holding the certificate that generates its own key and request: it has CSR and push attributes. */
    public Location seedKeyGeneratingLocation(Certificate certificate, String name) {
        return seedLocation(certificate, name, true);
    }

    /** A location holding the certificate that can only receive a pushed certificate. */
    public Location seedPushOnlyLocation(Certificate certificate, String name) {
        return seedLocation(certificate, name, false);
    }

    /** Links the certificate to the location, as a renewal in the location does with its successor. */
    public void seedLocationEntry(Location location, Certificate certificate) {
        CertificateLocation entry = new CertificateLocation();
        entry.setCertificate(certificate);
        entry.setLocation(location);
        certificateLocationRepository.save(entry);
    }

    /** Records that the successor renews the predecessor, as Core does when it requests the renewal. */
    public void seedRenewalRelation(Certificate predecessor, Certificate successor) {
        seedRelation(predecessor, successor, CertificateRelationType.RENEWAL);
    }

    private void seedRelation(Certificate predecessor, Certificate successor, CertificateRelationType type) {
        CertificateRelation relation = new CertificateRelation();
        relation.getId().setPredecessorCertificateUuid(predecessor.getUuid());
        relation.getId().setSuccessorCertificateUuid(successor.getUuid());
        relation.setPredecessorCertificate(predecessor);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(type);
        certificateRelationRepository.save(relation);
    }

    /** A location's renewal row whose renewal has started the given successor. */
    public CertificateRenewalLocation seedLocationRenewal(Certificate certificate, Location location,
            Certificate successor) {
        CertificateRenewalLocation row = new CertificateRenewalLocation();
        row.setCertificateUuid(certificate.getUuid());
        row.setLocationUuid(location.getUuid());
        row.setSuccessorUuid(successor.getUuid());
        return renewalLocationRepository.save(row);
    }

    public CertificateRenewalLocation locationRow(Certificate certificate, Location location) {
        return renewalLocationRepository
                .findByCertificateUuidAndLocationUuid(certificate.getUuid(), location.getUuid())
                .orElseThrow();
    }

    public CertificateRenewalInfo renewalRow(UUID certificateUuid) {
        return renewalInfoRepository.findByCertificateUuid(certificateUuid).orElseThrow();
    }

    /** A trigger whose only action renews the certificate, associated with the renewal due event. */
    public TriggerAssociation seedRenewTrigger(UUID ownerUuid) {
        Execution execution = newExecution(ExecutionType.RENEW_CERTIFICATE);
        execution.setItems(Set.of());
        executionRepository.save(execution);
        return seedTrigger(execution, ownerUuid);
    }

    /** A trigger whose only action removes the certificate's RA profile, associated with the renewal due event. */
    public TriggerAssociation seedRemoveRaProfileTrigger(UUID ownerUuid) {
        Execution execution = newExecution(ExecutionType.SET_FIELD);
        executionRepository.save(execution);
        ExecutionItem removeRaProfile = new ExecutionItem();
        removeRaProfile.setExecution(execution);
        removeRaProfile.setFieldSource(FilterFieldSource.PROPERTY);
        removeRaProfile.setFieldIdentifier(FilterField.RA_PROFILE_NAME.name());
        execution.setItems(Set.of(executionItemRepository.save(removeRaProfile)));
        return seedTrigger(execution, ownerUuid);
    }

    private static Execution newExecution(ExecutionType type) {
        Execution execution = new Execution();
        execution.setName(type.getCode() + "-" + UUID.randomUUID());
        execution.setType(type);
        execution.setResource(Resource.CERTIFICATE);
        return execution;
    }

    private TriggerAssociation seedTrigger(Execution execution, UUID ownerUuid) {
        Action action = new Action();
        action.setName("action-" + UUID.randomUUID());
        action.setResource(Resource.CERTIFICATE);
        action.setExecutions(Set.of(execution));
        actionRepository.save(action);

        Trigger trigger = new Trigger();
        trigger.setName("trigger-" + UUID.randomUUID());
        trigger.setType(TriggerType.EVENT);
        trigger.setResource(Resource.CERTIFICATE);
        trigger.setEvent(ResourceEvent.CERTIFICATE_RENEWAL_DUE);
        trigger.setRules(Set.of());
        trigger.setActions(Set.of(action));
        trigger = triggerRepository.save(trigger);

        TriggerAssociation association = new TriggerAssociation();
        association.setTriggerUuid(trigger.getUuid());
        association.setTrigger(trigger);
        association.setEvent(ResourceEvent.CERTIFICATE_RENEWAL_DUE);
        association.setTriggeredBy(ownerUuid);
        return triggerAssociationRepository.save(association);
    }

    private Location seedLocation(Certificate certificate, String name, boolean keyGenerating) {
        Location location = newLocation(seedEntity("http://localhost/" + UUID.randomUUID()), name);
        CertificateLocation entry = entry(certificate, location, List.of(locationAttribute()));
        if (keyGenerating) {
            entry.setCsrAttributes(List.of(locationAttribute()));
        }
        location.getCertificates().add(entry);
        return locationRepository.save(location);
    }

    private EntityInstanceReference seedEntity(String connectorUrl) {
        Connector connector = new Connector();
        connector.setName("location-connector-" + UUID.randomUUID());
        connector.setUrl(connectorUrl);
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);
        EntityInstanceReference entity = new EntityInstanceReference();
        entity.setEntityInstanceUuid(UUID.randomUUID().toString());
        entity.setConnector(connector);
        return entityInstanceReferenceRepository.save(entity);
    }

    private static Location newLocation(EntityInstanceReference entity, String name) {
        Location location = new Location();
        location.setUuid(UUID.randomUUID());
        location.setName(name);
        location.setEntityInstanceReference(entity);
        location.setEnabled(true);
        location.setSupportKeyManagement(true);
        location.setSupportMultipleEntries(true);
        return location;
    }

    private static CertificateLocation entry(Certificate certificate, Location location,
            List<BaseAttribute> pushAttributes) {
        CertificateLocation entry = new CertificateLocation();
        entry.setCertificate(certificate);
        entry.setLocation(location);
        entry.setPushAttributes(pushAttributes);
        return entry;
    }

    private AuthorityFixtures.Repos authorityRepos() {
        return new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                connectorInterfaceRepository);
    }

    private static DataAttributeV3 locationAttribute() {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName("attribute");
        attribute.setContent(List.of(new StringAttributeContentV3("data", "ref")));
        return attribute;
    }

    private void makeDue(UUID certificateUuid) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        renewalWindowWriter
                .write(certificateUuid, new WindowWrite.Forced(
                        new Window(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(10))), null));
        CertificateRenewalInfo row = renewalRow(certificateUuid);
        row.setRenewAt(now.minus(Duration.ofMinutes(1)));
        renewalInfoRepository.save(row);
    }

    private CertificateBuilder issuedCertificate(RaProfile raProfile) {
        CertificateContent content = new CertificateContent();
        content.setContent(UUID.randomUUID().toString());
        content = certificateContentRepository.save(content);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return aCertificate()
                .withSubjectDn("CN=auto-renewal")
                .withSerialNumber(UUID.randomUUID().toString())
                .withFingerprint(UUID.randomUUID().toString())
                .withState(CertificateState.ISSUED)
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withRaProfile(raProfile)
                .withRaProfileUuid(raProfile.getUuid())
                .withNotBefore(Date.from(now.minus(Duration.ofDays(60))))
                .withNotAfter(Date.from(now.plus(VALIDITY_LEFT)));
    }
}

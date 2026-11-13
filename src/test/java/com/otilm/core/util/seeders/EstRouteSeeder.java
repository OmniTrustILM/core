package com.otilm.core.util.seeders;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.util.builders.AuthorityFixtures;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;

/**
 * Seeds the profiles that an EST request is routed through: EST Profiles, RA Profiles whose authority has a connector,
 * the activation of EST on an RA Profile, and the system default, with the certificates that an EST Profile can trust
 * and the issued certificates that clients renew. Every method saves through the repositories and returns the saved
 * entity, so a test names only what its scenario depends on.
 * <p>
 * An RA Profile seeded on a WireMock server has that server's URL as its connector, and a connector URL is unique, so a
 * test seeds one such RA Profile. Every other RA Profile gets a URL that no request reaches.
 */
@Component
public class EstRouteSeeder {

    private static final String AUTHORITY_KIND = "MOCK";
    private static final String SYSTEM_DEFAULT_NAME = "est-default";

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateProtocolAssociationRepository protocolAssociationRepository;

    @Autowired
    private ProtocolCertificateAssociationsRepository protocolCertificateAssociationsRepository;

    @Autowired
    private CertificateRequestRepository certificateRequestRepository;

    @Autowired
    private CertificateRelationRepository certificateRelationRepository;

    @Autowired
    private CertificateInternalService certificateService;

    public EstProfile seedEstProfile(String name, boolean enabled, RaProfile defaultRaProfile) {
        return estProfileRepository
                .save(anEstProfile().withName(name).withEnabled(enabled).withRaProfile(defaultRaProfile).build());
    }

    /**
     * Seeds an enabled EST Profile that authenticates clients by the Basic credentials of the Secrets, issuing through
     * the RA Profile.
     */
    public EstProfile seedRaBasicEstProfile(String name, RaProfile defaultRaProfile, Secret... credentialSecrets) {
        return seedEstProfile(name, EstAuthenticationPolicy.RA_BASIC, defaultRaProfile, List.of(credentialSecrets),
                List.of());
    }

    /**
     * Seeds an enabled EST Profile of the authentication policy that issues through the RA Profile, references the
     * Secrets as RA credentials and trusts the CA certificates. The management API takes the Secrets only under
     * {@code raBasic} and the CA certificates only under the certificate policies, and the repository takes any
     * combination, so a test can give a profile the material of every policy.
     */
    public EstProfile seedEstProfile(String name, EstAuthenticationPolicy policy, RaProfile defaultRaProfile,
            List<Secret> credentialSecrets, List<Certificate> trustedCaCertificates) {
        UUID[] secretUuids = credentialSecrets.stream().map(Secret::getUuid).toArray(UUID[]::new);
        UUID[] certificateUuids = trustedCaCertificates.stream().map(Certificate::getUuid).toArray(UUID[]::new);
        return estProfileRepository
                .save(anEstProfile()
                        .withName(name)
                        .withEnabled(true)
                        .withRaProfile(defaultRaProfile)
                        .withAuthenticationPolicy(policy)
                        .withBasicCredentialSecrets(secretUuids)
                        .withTrustedCaCertificates(certificateUuids)
                        .build());
    }

    /**
     * Seeds an enabled EST Profile that issues through the RA Profile and whose certificate associations give every
     * certificate requested through it the owner and the groups.
     */
    public EstProfile seedEstProfileAssociatingCertificates(String name, RaProfile defaultRaProfile, UUID ownerUuid,
            UUID... groupUuids) {
        ProtocolCertificateAssociations associations = new ProtocolCertificateAssociations();
        associations.setOwnerUuid(ownerUuid);
        associations.setGroupUuids(new ArrayList<>(List.of(groupUuids)));
        ProtocolCertificateAssociations savedAssociations = protocolCertificateAssociationsRepository
                .save(associations);
        return estProfileRepository
                .save(anEstProfile()
                        .withName(name)
                        .withEnabled(true)
                        .withRaProfile(defaultRaProfile)
                        .withCertificateAssociations(savedAssociations)
                        .build());
    }

    /** Stores the certificate in the inventory as an import leaves it, so that an EST Profile can trust it. */
    public Certificate seedCertificate(X509Certificate certificate) {
        return certificateRepository.save(certificateService.createCertificateEntity(certificate));
    }

    /**
     * Stores the certificate in the inventory as issued through the RA Profile, with validation status {@code VALID},
     * and attributed to no protocol.
     */
    public Certificate seedIssuedCertificate(X509Certificate certificate, RaProfile raProfile) {
        Certificate issued = certificateService.createCertificateEntity(certificate);
        issued.setRaProfile(raProfile);
        issued.setState(CertificateState.ISSUED);
        issued.setValidationStatus(CertificateValidationStatus.VALID);
        return certificateRepository.save(issued);
    }

    /**
     * Stores the certificate in the inventory as an enrolment through the EST Profile leaves it: issued through the RA
     * Profile, with validation status {@code VALID}, and attributed to the EST Profile. Only the attribution is
     * recorded; the profile's certificate associations are not applied.
     */
    public Certificate seedIssuedCertificate(X509Certificate certificate, RaProfile raProfile, EstProfile estProfile) {
        return seedIssuedCertificate(certificate, raProfile, CertificateProtocolInfo.est(estProfile.getUuid()));
    }

    /**
     * Stores the certificate in the inventory as a protocol leaves the certificate it obtained: issued through the RA
     * Profile, with validation status {@code VALID}, and attributed to the protocol, its profile and, for ACME, the
     * account. Only the attribution is recorded; the profile's certificate associations are not applied.
     */
    public Certificate seedIssuedCertificate(X509Certificate certificate, RaProfile raProfile,
            CertificateProtocolInfo protocolInfo) {
        return attributeToProtocol(seedIssuedCertificate(certificate, raProfile), protocolInfo);
    }

    /**
     * Records that the protocol issued the saved certificate, with its profile and, for ACME, the account. Only the
     * attribution is recorded; the profile's certificate associations are not applied.
     */
    public Certificate attributeToProtocol(Certificate certificate, CertificateProtocolInfo protocolInfo) {
        CertificateProtocolAssociation attribution = new CertificateProtocolAssociation();
        attribution.setCertificate(certificate);
        attribution.setProtocol(protocolInfo.getProtocol());
        attribution.setProtocolProfileUuid(protocolInfo.getProtocolProfileUuid());
        attribution.setAdditionalProtocolUuid(protocolInfo.getAdditionalProtocolUuid());
        certificate.setProtocolAssociation(protocolAssociationRepository.save(attribution));
        return certificate;
    }

    /**
     * Stores the certificate that the source was renewed into, as the platform leaves it: on the RA Profile, in the
     * state, carrying the request, and related to the source by the relation type. A successor that has not been issued
     * carries {@code PENDING}; issuing rewrites it.
     *
     * @param requestDer the DER of the request that the successor carries
     */
    public Certificate seedSuccessor(Certificate source, RaProfile raProfile, byte[] requestDer, CertificateState state,
            CertificateRelationType relationType) {
        CertificateRequestEntity request = certificateRequestRepository
                .save(aCertificateRequest().withContent(Base64.getEncoder().encodeToString(requestDer)).build());
        Certificate successor = certificateRepository
                .save(aCertificate()
                        .withFingerprint("successor-" + UUID.randomUUID())
                        .withState(state)
                        .withRaProfile(raProfile)
                        .withCertificateRequestUuid(request.getUuid())
                        .build());
        CertificateRelation relation = new CertificateRelation();
        relation.setPredecessorCertificate(source);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(relationType);
        certificateRelationRepository.save(relation);
        return successor;
    }

    /** Seeds the enabled EST Profile that serves a request without a label, issuing through the RA Profile. */
    public EstProfile seedSystemDefault(RaProfile defaultRaProfile) {
        return markAsSystemDefault(seedEstProfile(SYSTEM_DEFAULT_NAME, true, defaultRaProfile));
    }

    public EstProfile markAsSystemDefault(EstProfile estProfile) {
        estProfile.setSystemDefault(true);
        return estProfileRepository.save(estProfile);
    }

    public RaProfile activateEst(RaProfile raProfile, EstProfile estProfile) {
        raProfile.setEstProfile(estProfile);
        return raProfileRepository.save(raProfile);
    }

    /** Seeds an enabled RA Profile on a v2 authority whose connector no request reaches. */
    public RaProfile seedRaProfile(String name) {
        return seedRaProfile(name, true);
    }

    /**
     * @param enabled whether the RA Profile is enabled, {@code null} for one that has never been set
     */
    public RaProfile seedRaProfile(String name, Boolean enabled) {
        return rename(AuthorityFixtures.v2Authority(authorityRepos(), AUTHORITY_KIND), name, enabled);
    }

    /** Seeds an enabled RA Profile on a v2 authority that has the WireMock server as its connector. */
    public RaProfile seedRaProfile(WireMockServer connector, String name) {
        return rename(AuthorityFixtures.v2Authority(authorityRepos(), connector, AUTHORITY_KIND), name, true);
    }

    /**
     * Seeds an enabled RA Profile on a v3 authority that has the WireMock server as its connector.
     *
     * @param features the feature flags that the authority advertises
     */
    public RaProfile seedRaProfileOnV3Authority(WireMockServer connector, String name, FeatureFlag... features) {
        return rename(AuthorityFixtures.v3Authority(authorityRepos(), connector, features), name, true);
    }

    /** Seeds an enabled RA Profile whose authority has lost its connector. */
    public RaProfile seedRaProfileWithoutConnector(String name) {
        AuthorityFixtures.Fixture fixture = AuthorityFixtures.v2Authority(authorityRepos(), AUTHORITY_KIND);
        AuthorityInstanceReference authority = fixture.authority();
        authority.setConnector(null);
        authorityInstanceReferenceRepository.save(authority);
        return rename(fixture, name, true);
    }

    /** Seeds an enabled RA Profile that has no authority. */
    public RaProfile seedRaProfileWithoutAuthority(String name) {
        RaProfile raProfile = new RaProfile();
        raProfile.setName(name);
        raProfile.setEnabled(true);
        return raProfileRepository.save(raProfile);
    }

    private RaProfile rename(AuthorityFixtures.Fixture authority, String name, Boolean enabled) {
        RaProfile raProfile = authority.raProfile();
        raProfile.setName(name);
        raProfile.setEnabled(enabled);
        return raProfileRepository.save(raProfile);
    }

    private AuthorityFixtures.Repos authorityRepos() {
        return new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                connectorInterfaceRepository);
    }
}

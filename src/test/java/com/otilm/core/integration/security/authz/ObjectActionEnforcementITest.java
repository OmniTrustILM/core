package com.otilm.core.integration.security.authz;

import com.otilm.api.model.client.certificate.CertificateUpdateObjectsDto;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.key.BulkKeyUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.EditKeyRequestDto;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.core.auth.ObjectAllowedActionsDto;
import com.otilm.api.model.core.auth.ObjectAllowedActionsRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authz.ObjectActionRequirements;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CommentExternalService;
import com.otilm.core.service.ComplianceInternalService;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.CryptographicOperationExternalService;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Calls the endpoints that perform each reported action as several kinds of user, and checks that an action is reported
 * exactly when its endpoints accept it. An endpoint accepts a call when it fails for any reason other than
 * authorization, since the fixtures carry nothing an operation could complete with.
 */
class ObjectActionEnforcementITest extends BaseSpringBootTest {

    /** Resources reached only as the parent or relative of a certificate or key, which every user here may use. */
    private static final Set<String> SURROUNDINGS = Set
            .of(Resource.RA_PROFILE.getCode(), Resource.AUTHORITY.getCode(), Resource.TOKEN.getCode(),
                    Resource.TOKEN_PROFILE.getCode());

    private static final Set<String> READ_ACTIONS = Set
            .of(ResourceAction.LIST.getCode(), ResourceAction.DETAIL.getCode(), ResourceAction.MEMBERS.getCode());

    enum User {
        FULLY_PRIVILEGED,
        READ_ONLY,
        OBJECT_GRANT,
        OWNER,
        GROUP_MEMBER
    }

    @FunctionalInterface
    private interface Call {
        void run() throws Exception;
    }

    /** An endpoint call and the checks it must have asked before any failure that is not a refusal. */
    private record Endpoint(Call call, Set<String> reaches) {
    }

    private final List<String> asked = new ArrayList<>();

    @Autowired
    private ResourceExternalService resourceService;

    @Autowired
    private CertificateExternalService certificateService;

    @Autowired
    private CertificateInternalService certificateInternalService;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private CryptographicKeyExternalService keyService;

    @Autowired
    private CryptographicOperationExternalService cryptographicOperationService;

    @Autowired
    private ClientOperationExternalService clientOperationExternalService;

    @Autowired
    private CryptographicKeyExportExternalService keyExportService;

    @Autowired
    private CommentExternalService commentService;

    @Autowired
    private ComplianceInternalService complianceService;

    @Autowired
    private TokenProfileSeeder tokenProfileSeeder;

    @Autowired
    private CryptographicKeySeeder keySeeder;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private GroupAssociationRepository groupAssociationRepository;

    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    private RaProfile raProfile;

    private UUID certificateUuid;

    private CryptographicKey key;

    private UUID groupUuid;

    @BeforeEach
    void createCertificateKeyAndGroup() {
        Connector connector = connectorRepository
                .save(aConnector().withGeneratedUuid().withName("connector").withVersion(ConnectorVersion.V1).build());

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setName("authority");
        authority.setConnector(connector);
        authority = authorityRepository.save(authority);
        raProfile = new RaProfile();
        raProfile.setName("ra-profile");
        raProfile.setAuthorityInstanceReference(authority);
        raProfile.setAuthorityInstanceReferenceUuid(authority.getUuid());
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);

        CertificateContent content = certificateContentRepository.save(new CertificateContent());
        certificateUuid = certificateRepository
                .save(aCertificate()
                        .withSerialNumber(UUID.randomUUID().toString())
                        .withCertificateContent(content)
                        .withCertificateContentId(content.getId())
                        .withState(CertificateState.REQUESTED)
                        .withRaProfile(raProfile)
                        .build())
                .getUuid();

        TokenProfile tokenProfile = tokenProfileSeeder.seedTokenProfile();
        key = keySeeder.seedKey("key", tokenProfile, tokenProfile.getTokenInstanceReference());

        Group group = new Group();
        group.setName("group");
        groupUuid = groupRepository.save(group).getUuid();
    }

    @ParameterizedTest
    @EnumSource(User.class)
    void reportsCertificateActionExactly_whenItsEndpointsAcceptIt(User user) {
        // given
        actAs(user, Resource.CERTIFICATE, certificateUuid);
        Map<ResourceAction, List<Endpoint>> endpoints = certificateEndpoints();

        // when
        List<ResourceAction> reported = reportedActions(Resource.CERTIFICATE, certificateUuid);

        // then
        assertThat(endpoints.keySet()).containsExactlyInAnyOrderElementsOf(tabledActions(Resource.CERTIFICATE));
        assertReportedExactlyWhenAccepted(user, reported, endpoints);
    }

    @ParameterizedTest
    @EnumSource(User.class)
    void reportsKeyActionExactly_whenItsEndpointsAcceptIt(User user) {
        // given
        actAs(user, Resource.CRYPTOGRAPHIC_KEY, key.getUuid());
        Map<ResourceAction, List<Endpoint>> endpoints = keyEndpoints();

        // when
        List<ResourceAction> reported = reportedActions(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(endpoints.keySet()).containsExactlyInAnyOrderElementsOf(tabledActions(Resource.CRYPTOGRAPHIC_KEY));
        assertReportedExactlyWhenAccepted(user, reported, endpoints);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** Ordered so the endpoints changing the certificate run last, archive restored and delete at the very end. */
    private Map<ResourceAction, List<Endpoint>> certificateEndpoints() {
        SecuredParentUUID authority = SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid());
        SecuredUUID raProfileUuid = SecuredUUID.fromUUID(raProfile.getUuid());
        SecuredUUID certificate = SecuredUUID.fromUUID(certificateUuid);
        Map<ResourceAction, List<Endpoint>> endpoints = new LinkedHashMap<>();
        endpoints
                .put(ResourceAction.DETAIL,
                        List
                                .of(endpoint(() -> certificateService.getCertificate(certificate),
                                        check(Resource.CERTIFICATE, ResourceAction.DETAIL),
                                        check(Resource.RA_PROFILE, ResourceAction.MEMBERS)),
                                        endpoint(() -> certificateService.listLocations(certificate),
                                                check(Resource.CERTIFICATE, ResourceAction.DETAIL))));
        endpoints
                .put(ResourceAction.UPDATE, List
                        .of(endpoint(
                                () -> certificateService
                                        .updateCertificateObjects(certificate, new CertificateUpdateObjectsDto()),
                                check(Resource.CERTIFICATE, ResourceAction.UPDATE))));
        // The compliance check endpoint logs a refused compliance profile check instead of failing, so that check is
        // called directly; the guard snapshot pins that checkCompliance calls it.
        endpoints
                .put(ResourceAction.CHECK_COMPLIANCE, List
                        .of(endpoint(() -> certificateService.checkCompliance(List.of(certificate)),
                                check(Resource.CERTIFICATE, ResourceAction.CHECK_COMPLIANCE)),
                                endpoint(
                                        () -> complianceService
                                                .checkResourceObjectCompliance(Resource.CERTIFICATE, certificateUuid),
                                        check(Resource.COMPLIANCE_PROFILE, ResourceAction.CHECK_COMPLIANCE))));
        // Renewal reaches its create check only past CSR validation, which this fixture cannot pass, so the create
        // check is called directly; the guard snapshot pins that renewCertificate calls it.
        endpoints
                .put(ResourceAction.RENEW,
                        List
                                .of(endpoint(
                                        () -> clientOperationService
                                                .renewCertificate(authority, raProfileUuid, certificateUuid.toString(),
                                                        new ClientCertificateRenewRequestDto()),
                                        check(Resource.RA_PROFILE, ResourceAction.DETAIL),
                                        check(Resource.AUTHORITY, ResourceAction.DETAIL)),
                                        endpoint(certificateInternalService::checkCreatePermissions,
                                                check(Resource.CERTIFICATE, ResourceAction.CREATE)),
                                        endpoint(
                                                () -> clientOperationService
                                                        .renewCertificateAction(UUID.randomUUID(),
                                                                new ClientCertificateRenewRequestDto(), false),
                                                check(Resource.CERTIFICATE, ResourceAction.RENEW))));
        // Issuing reaches its issue, create and detail checks only past request validation, so they are called
        // directly; the guard snapshot pins that issueExistingCertificate calls them.
        endpoints
                .put(ResourceAction.ISSUE, List
                        .of(endpoint(
                                () -> clientOperationExternalService
                                        .issueExistingCertificate(authority, raProfileUuid, certificateUuid.toString(),
                                                new ClientCertificateIssueRequestDto()),
                                check(Resource.RA_PROFILE, ResourceAction.DETAIL),
                                check(Resource.AUTHORITY, ResourceAction.DETAIL)),
                                endpoint(certificateInternalService::checkIssuePermissions,
                                        check(Resource.CERTIFICATE, ResourceAction.ISSUE)),
                                endpoint(certificateInternalService::checkCreatePermissions,
                                        check(Resource.CERTIFICATE, ResourceAction.CREATE)),
                                endpoint(() -> certificateInternalService.getCertificateEntity(certificate),
                                        check(Resource.CERTIFICATE, ResourceAction.DETAIL),
                                        check(Resource.RA_PROFILE, ResourceAction.MEMBERS))));
        endpoints
                .put(ResourceAction.REVOKE,
                        List
                                .of(endpoint(
                                        () -> clientOperationService
                                                .revokeCertificate(authority, raProfileUuid, certificateUuid.toString(),
                                                        new ClientCertificateRevocationDto()),
                                        check(Resource.RA_PROFILE, ResourceAction.DETAIL),
                                        check(Resource.AUTHORITY, ResourceAction.DETAIL)),
                                        endpoint(
                                                () -> clientOperationService
                                                        .revokeCertificateAction(UUID.randomUUID(),
                                                                new ClientCertificateRevocationDto(), false),
                                                check(Resource.CERTIFICATE, ResourceAction.REVOKE))));
        endpoints.put(ResourceAction.COMMENT, List.of(comment(Resource.CERTIFICATE, certificateUuid)));
        endpoints
                .put(ResourceAction.ARCHIVE,
                        List
                                .of(endpoint(() -> certificateService.archiveCertificate(certificate),
                                        check(Resource.CERTIFICATE, ResourceAction.ARCHIVE)),
                                        endpoint(() -> certificateService.unarchiveCertificate(certificate),
                                                check(Resource.CERTIFICATE, ResourceAction.ARCHIVE))));
        endpoints
                .put(ResourceAction.DELETE,
                        List
                                .of(endpoint(() -> certificateService.deleteCertificate(certificate),
                                        check(Resource.CERTIFICATE, ResourceAction.DELETE))));
        return endpoints;
    }

    /** Ordered so the endpoints changing the key run last, and removal from the inventory at the very end. */
    private Map<ResourceAction, List<Endpoint>> keyEndpoints() {
        SecuredParentUUID token = SecuredParentUUID.fromUUID(key.getTokenInstanceReferenceUuid());
        SecuredUUID tokenProfile = SecuredUUID.fromUUID(key.getTokenProfileUuid());
        SecuredUUID keyUuid = SecuredUUID.fromUUID(key.getUuid());
        String[] operationChecks = {
                check(Resource.TOKEN, ResourceAction.DETAIL),
                check(Resource.TOKEN_PROFILE, ResourceAction.DETAIL)};
        Map<ResourceAction, List<Endpoint>> endpoints = new LinkedHashMap<>();
        endpoints
                .put(ResourceAction.DETAIL,
                        List
                                .of(endpoint(() -> keyService.getKey(keyUuid),
                                        check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL),
                                        check(Resource.TOKEN, ResourceAction.MEMBERS)),
                                        endpoint(() -> keyService.getEventHistory(key.getUuid(), UUID.randomUUID()),
                                                check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL))));
        endpoints
                .put(ResourceAction.EXPORT_KEY, List
                        .of(endpoint(() -> keyExportService.listExportKeyAttributes(key.getUuid(), UUID.randomUUID()),
                                check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.EXPORT_KEY))));
        endpoints
                .put(ResourceAction.SIGN,
                        List
                                .of(endpoint(() -> cryptographicOperationService
                                        .signData(token, tokenProfile, key.getUuid(), UUID.randomUUID(),
                                                new SignDataRequestDto()),
                                        operationChecks)));
        endpoints
                .put(ResourceAction.VERIFY,
                        List
                                .of(endpoint(() -> cryptographicOperationService
                                        .verifyData(token, tokenProfile, key.getUuid(), UUID.randomUUID(),
                                                new VerifyDataRequestDto()),
                                        operationChecks)));
        endpoints
                .put(ResourceAction.ENCRYPT,
                        List
                                .of(endpoint(() -> cryptographicOperationService
                                        .encryptData(token, tokenProfile, key.getUuid(), UUID.randomUUID(),
                                                new CipherDataRequestDto()),
                                        operationChecks)));
        endpoints
                .put(ResourceAction.DECRYPT,
                        List
                                .of(endpoint(() -> cryptographicOperationService
                                        .decryptData(token, tokenProfile, key.getUuid(), UUID.randomUUID(),
                                                new CipherDataRequestDto()),
                                        operationChecks)));
        endpoints.put(ResourceAction.COMMENT, List.of(comment(Resource.CRYPTOGRAPHIC_KEY, key.getUuid())));
        endpoints
                .put(ResourceAction.UPDATE,
                        List
                                .of(endpoint(() -> keyService.editKey(keyUuid, new EditKeyRequestDto()),
                                        check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE)),
                                        endpoint(() -> keyService.updateKeyUsages(bulkUsage()),
                                                check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE))));
        endpoints
                .put(ResourceAction.ENABLE,
                        List
                                .of(endpoint(() -> keyService.enableKey(key.getUuid(), List.of()),
                                        check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.ENABLE)),
                                        endpoint(() -> keyService.enableKey(List.of(key.getUuid().toString())),
                                                check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.ENABLE))));
        endpoints
                .put(ResourceAction.DELETE, List
                        .of(endpoint(() -> keyService.deleteKey(key.getUuid(), List.of(UUID.randomUUID().toString())),
                                check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE)),
                                endpoint(() -> keyService.removeKeyFromInventory(keyUuid),
                                        check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE))));
        return endpoints;
    }

    private BulkKeyUsageRequestDto bulkUsage() {
        BulkKeyUsageRequestDto request = new BulkKeyUsageRequestDto();
        request.setUuids(List.of(key.getUuid()));
        request.setUsage(List.of());
        return request;
    }

    private Endpoint comment(Resource resource, UUID objectUuid) {
        CommentCreateRequestDto request = new CommentCreateRequestDto();
        request.setBody("comment");
        return endpoint(() -> commentService
                .createComment(SecuredResource.fromResource(resource), SecuredUUID.fromUUID(objectUuid), request),
                check(resource, ResourceAction.COMMENT));
    }

    private static Set<ResourceAction> tabledActions(Resource resource) {
        return ObjectActionRequirements.of(resource).orElseThrow().actions().keySet();
    }

    private List<ResourceAction> reportedActions(Resource resource, UUID objectUuid) {
        return resourceService
                .listObjectAllowedActions(resource, new ObjectAllowedActionsRequestDto(List.of(objectUuid)))
                .getItems()
                .stream()
                .findFirst()
                .map(ObjectAllowedActionsDto::getAllowedActions)
                .orElse(List.of());
    }

    private void assertReportedExactlyWhenAccepted(User user, List<ResourceAction> reported,
            Map<ResourceAction, List<Endpoint>> endpoints) {
        List<String> mismatches = new ArrayList<>();
        endpoints.forEach((action, calls) -> {
            boolean accepted = calls.stream().allMatch(this::accepts);
            if (accepted != reported.contains(action)) {
                mismatches
                        .add("%s %s, endpoints %s"
                                .formatted(action.getCode(), accepted ? "not reported" : "reported",
                                        accepted ? "accept it" : "refuse it"));
            }
        });
        assertThat(mismatches).as(user.name()).isEmpty();
    }

    private boolean accepts(Endpoint endpoint) {
        asked.clear();
        try {
            endpoint.call().run();
            return true;
        } catch (AccessDeniedException e) {
            return false;
        } catch (Exception e) {
            assertThat(asked).as("checks asked before the endpoint failed with %s", e).containsAll(endpoint.reaches());
            return true;
        }
    }

    private static Endpoint endpoint(Call call, String... reaches) {
        return new Endpoint(call, Set.of(reaches));
    }

    private static String check(Resource resource, ResourceAction action) {
        return resource.getCode() + ":" + action.getCode();
    }

    private void actAs(User user, Resource resource, UUID objectUuid) {
        Predicate<OpaRequestedResource> grants = switch (user) {
            case FULLY_PRIVILEGED -> request -> true;
            case READ_ONLY -> request -> READ_ACTIONS.contains(action(request));
            case OBJECT_GRANT -> request -> SURROUNDINGS.contains(name(request))
                    || (resource.getCode().equals(name(request)) && request.getObjectUUIDs() != null
                            && List.of(objectUuid.toString()).equals(request.getObjectUUIDs()));
            case OWNER -> request -> SURROUNDINGS.contains(name(request));
            case GROUP_MEMBER ->
                request -> SURROUNDINGS.contains(name(request)) || (Resource.GROUP.getCode().equals(name(request))
                        && ResourceAction.MEMBERS.getCode().equals(action(request)));
        };
        when(opaClient.checkResourceAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenAnswer(invocation -> {
                    OpaRequestedResource request = invocation.getArgument(1);
                    asked.add(name(request) + ":" + action(request));
                    OpaResourceAccessResult result = new OpaResourceAccessResult();
                    result.setAuthorized(grants.test(request));
                    result.setAllow(List.of());
                    return result;
                });
        if (user == User.OWNER) {
            OwnerAssociation owner = new OwnerAssociation();
            owner.setResource(resource);
            owner.setObjectUuid(objectUuid);
            owner.setOwnerUuid(UUID.fromString(currentUserUuid()));
            owner.setOwnerUsername("owner");
            ownerAssociationRepository.save(owner);
        }
        if (user == User.GROUP_MEMBER) {
            GroupAssociation association = new GroupAssociation();
            association.setResource(resource);
            association.setObjectUuid(objectUuid);
            association.setGroupUuid(groupUuid);
            groupAssociationRepository.save(association);
        }
    }

    private static String name(OpaRequestedResource request) {
        return request.getProperties().get("name");
    }

    private static String action(OpaRequestedResource request) {
        return request.getProperties().get("action");
    }

    private static String currentUserUuid() {
        return ((PlatformAuthenticationToken) SecurityContextHolder.getContext().getAuthentication())
                .getPrincipal()
                .getUserUuid();
    }
}

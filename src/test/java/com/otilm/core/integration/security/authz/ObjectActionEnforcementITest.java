package com.otilm.core.integration.security.authz;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.ObjectAllowedActionsDto;
import com.otilm.api.model.core.auth.ObjectAllowedActionsRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
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
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.CryptographicOperationExternalService;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.BaseSpringBootTest;
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
import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
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
    private TokenInstanceReferenceRepository tokenRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private CryptographicKeyRepository keyRepository;

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

        TokenInstanceReference token = new TokenInstanceReference();
        token.setName("token");
        token.setTokenInstanceUuid(UUID.randomUUID().toString());
        token.setConnector(connector);
        token.setStatus(TokenInstanceStatus.CONNECTED);
        token = tokenRepository.save(token);
        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("token-profile");
        tokenProfile.setTokenInstanceReference(token);
        tokenProfile.setTokenInstanceReferenceUuid(token.getUuid());
        tokenProfile.setEnabled(true);
        tokenProfile = tokenProfileRepository.save(tokenProfile);
        key = aCryptographicKey().withName("key").build();
        key.setTokenInstanceReference(token);
        key.setTokenProfile(tokenProfile);
        key = keyRepository.save(key);

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
        assertReportedExactlyWhenAccepted(user, reported, endpoints);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private Map<ResourceAction, List<Endpoint>> certificateEndpoints() {
        SecuredParentUUID authority = SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid());
        SecuredUUID raProfileUuid = SecuredUUID.fromUUID(raProfile.getUuid());
        Map<ResourceAction, List<Endpoint>> endpoints = new LinkedHashMap<>();
        endpoints
                .put(ResourceAction.DETAIL, List
                        .of(endpoint(() -> certificateService.getCertificate(SecuredUUID.fromUUID(certificateUuid)),
                                check(Resource.CERTIFICATE, ResourceAction.DETAIL),
                                check(Resource.RA_PROFILE, ResourceAction.MEMBERS))));
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
        return endpoints;
    }

    private Map<ResourceAction, List<Endpoint>> keyEndpoints() {
        Map<ResourceAction, List<Endpoint>> endpoints = new LinkedHashMap<>();
        endpoints
                .put(ResourceAction.DETAIL,
                        List
                                .of(endpoint(() -> keyService.getKey(SecuredUUID.fromUUID(key.getUuid())),
                                        check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL),
                                        check(Resource.TOKEN, ResourceAction.MEMBERS)),
                                        endpoint(() -> keyService.getEventHistory(key.getUuid(), UUID.randomUUID()),
                                                check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL))));
        endpoints
                .put(ResourceAction.SIGN, List
                        .of(endpoint(
                                () -> cryptographicOperationService
                                        .signData(SecuredParentUUID.fromUUID(key.getTokenInstanceReferenceUuid()),
                                                SecuredUUID.fromUUID(key.getTokenProfileUuid()), key.getUuid(),
                                                UUID.randomUUID(), new SignDataRequestDto()),
                                check(Resource.TOKEN, ResourceAction.DETAIL),
                                check(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.SIGN),
                                check(Resource.TOKEN_PROFILE, ResourceAction.DETAIL))));
        return endpoints;
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

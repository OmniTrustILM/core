package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.util.AuthenticationTokenTestHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ExternalAuthorizationCoreTest {

    @Mock
    OpaClient opaClient;

    @Mock
    GroupAssociationRepository groupAssociationRepository;

    @Mock
    OwnerAssociationRepository ownerAssociationRepository;

    ObjectMapper om = new ObjectMapper();

    ExternalAuthorizationCore core;

    @BeforeEach
    void setUp() {
        core = new ExternalAuthorizationCore(opaClient, om, groupAssociationRepository, ownerAssociationRepository);
    }

    @Test
    void grantsAccessWhenOpaAuthorizesDirectCheck() {
        // given
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(accessGranted());
        SecuredUUID uuid = SecuredUUID.fromUUID(UUID.randomUUID());
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(Resource.TOKEN, ResourceAction.DETAIL, List.of(uuid));

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(null), request);

        // then
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void deniesAccessWhenOpaRequestFails() {
        // given
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenThrow(new RuntimeException("OPA unreachable"));
        SecuredUUID uuid = SecuredUUID.fromUUID(UUID.randomUUID());
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(Resource.TOKEN, ResourceAction.DETAIL, List.of(uuid));

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(null), request);

        // then
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void deniesAccessForUnrecognizedAuthenticationType() {
        // given
        Authentication authentication = mock(Authentication.class);
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(Resource.TOKEN, ResourceAction.DETAIL, List.of());

        // when
        AuthorizationDecision decision = core.decide(authentication, request);

        // then
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void deniesAccessForNullAuthentication() {
        // given: no authenticated principal in the security context (SecurityContextHolder returns null)
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(Resource.TOKEN, ResourceAction.DETAIL, List.of());

        // when
        AuthorizationDecision decision = core.decide(null, request);

        // then: fail closed — the instanceof guard rejects null before any OPA call
        assertThat(decision.isGranted()).isFalse();
        verifyNoInteractions(opaClient);
    }

    @Test
    void deniesAnonymousAccessWhenPrincipalSerializationFails() throws JsonProcessingException {
        // given: a broken ObjectMapper simulates the anonymous-principal serialization failure path
        ObjectMapper brokenMapper = mock(ObjectMapper.class);
        when(brokenMapper.writeValueAsString(any())).thenThrow(new JsonProcessingException("boom") {
        });
        ExternalAuthorizationCore coreWithBrokenMapper =
                new ExternalAuthorizationCore(opaClient, brokenMapper, groupAssociationRepository, ownerAssociationRepository);
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(Resource.TOKEN, ResourceAction.DETAIL, List.of());

        // when
        AuthorizationDecision decision = coreWithBrokenMapper.decide(AuthenticationTokenTestHelper.getAnonymousToken("anonymousUser"), request);

        // then
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void fallbackSkippedWhenResourceHasNeitherOwnerNorGroups() {
        // given: TOKEN has no owner/group associations, so the fallback must not consult any repository
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(OpaResourceAccessResult.unauthorized());
        SecuredUUID uuid = SecuredUUID.fromUUID(UUID.randomUUID());
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(Resource.TOKEN, ResourceAction.DETAIL, List.of(uuid));

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then
        assertThat(decision.isGranted()).isFalse();
        verifyNoInteractions(ownerAssociationRepository, groupAssociationRepository);
    }

    @Test
    void ownerFallbackGrantsWhenAllObjectsOwnedByPrincipal() {
        // given
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(OpaResourceAccessResult.unauthorized());
        UUID userUuid = UUID.randomUUID();
        SecuredUUID objectUuid = SecuredUUID.fromUUID(UUID.randomUUID());
        AuthorizationRequest request = AuthorizationRequest.forDirectCheck(Resource.CERTIFICATE, ResourceAction.DETAIL, List.of(objectUuid));
        when(ownerAssociationRepository.countByOwnerUuidAndResourceAndObjectUuidIn(eq(userUuid), eq(Resource.CERTIFICATE), any()))
                .thenReturn(1L);

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(userUuid.toString()), request);

        // then
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void groupFallbackGrantsWhenAllGroupsAreAuthorized() {
        // given: not owned, but the object's group has the required member permission
        AuthorizationRequest request = directCheckWithNonMatchingOwner();
        UUID objectUuid = request.objectUuids().getFirst().getValue();

        GroupAssociation groupAssociation = new GroupAssociation();
        UUID groupUuid = UUID.randomUUID();
        groupAssociation.setGroupUuid(groupUuid);
        when(groupAssociationRepository.findByResourceAndObjectUuid(Resource.CERTIFICATE, objectUuid))
                .thenReturn(List.of(groupAssociation));

        when(opaClient.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(OpaResourceAccessResult.unauthorized()) // direct check
                .thenReturn(accessGranted());                       // group-member check

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void groupFallbackDeniesWhenObjectHasNoGroups() {
        // given
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(OpaResourceAccessResult.unauthorized());
        AuthorizationRequest request = directCheckWithNonMatchingOwner();
        UUID objectUuid = request.objectUuids().getFirst().getValue();
        when(groupAssociationRepository.findByResourceAndObjectUuid(Resource.CERTIFICATE, objectUuid))
                .thenReturn(List.of());

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void groupFallbackDeniesWhenGroupMemberCheckIsDenied() {
        // given
        AuthorizationRequest request = directCheckWithNonMatchingOwner();
        UUID objectUuid = request.objectUuids().getFirst().getValue();

        GroupAssociation groupAssociation = new GroupAssociation();
        groupAssociation.setGroupUuid(UUID.randomUUID());
        when(groupAssociationRepository.findByResourceAndObjectUuid(Resource.CERTIFICATE, objectUuid))
                .thenReturn(List.of(groupAssociation));

        when(opaClient.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(OpaResourceAccessResult.unauthorized()) // direct check
                .thenReturn(OpaResourceAccessResult.unauthorized()); // group-member check

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void fallbackGrantsWhenSecurityFilterAppliedWithNoObjectUuids() {
        // given: an owner/group-capable resource, security-filter scope, but no specific object uuids
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(OpaResourceAccessResult.unauthorized());
        AuthorizationRequest request = new AuthorizationRequest(
                Map.of("action", ResourceAction.LIST.getCode(), "name", Resource.CERTIFICATE.getCode(),
                        "parentAction", ResourceAction.NONE.getCode(), "parentName", Resource.NONE.getCode()),
                List.of(),
                List.of(),
                true,
                Optional.empty(),
                "certificates:list");

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then
        assertThat(decision.isGranted()).isTrue();
    }

    @Test
    void fallbackDeniesOnUnsupportedResourceCode() {
        // given: a request whose resource/action codes are not registered platform enums
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(OpaResourceAccessResult.unauthorized());
        AuthorizationRequest request = new AuthorizationRequest(
                Map.of("action", "bogusAction", "name", "bogusResource",
                        "parentAction", ResourceAction.NONE.getCode(), "parentName", Resource.NONE.getCode()),
                List.of(SecuredUUID.fromUUID(UUID.randomUUID())),
                List.of(),
                false,
                Optional.empty(),
                "bogusResource:bogusAction");

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then
        assertThat(decision.isGranted()).isFalse();
    }

    @Test
    void parentDenialShortCircuitsBeforeChildCheck() {
        // given: the parent-resource check is denied
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(OpaResourceAccessResult.unauthorized());
        AuthorizationRequest request = requestWithParent(
                List.of(SecuredUUID.fromUUID(UUID.randomUUID())),
                List.of(SecuredUUID.fromUUID(UUID.randomUUID())));

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then: denied, and OPA was consulted only once — for the parent resource, with the parent UUIDs
        assertThat(decision.isGranted()).isFalse();
        ArgumentCaptor<OpaRequestedResource> opaResource = ArgumentCaptor.forClass(OpaRequestedResource.class);
        verify(opaClient).checkResourceAccess(any(), opaResource.capture(), any(), any());
        assertThat(opaResource.getValue().getProperties())
                .containsEntry("name", Resource.TOKEN_PROFILE.getCode())
                .containsEntry("action", ResourceAction.DETAIL.getCode());
        assertThat(opaResource.getValue().getObjectUUIDs()).containsExactly(request.parentUuids().getFirst().toString());
    }

    @Test
    void childCheckedWithObjectUuidsAfterParentGranted() {
        // given: the parent check is granted, the child check is denied
        when(opaClient.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(accessGranted())                        // parent check
                .thenReturn(OpaResourceAccessResult.unauthorized()); // child check
        AuthorizationRequest request = requestWithParent(
                List.of(SecuredUUID.fromUUID(UUID.randomUUID())),
                List.of(SecuredUUID.fromUUID(UUID.randomUUID())));

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then: parent checked first (parent UUIDs), then the child resource with the object UUIDs; child denial wins
        assertThat(decision.isGranted()).isFalse();
        ArgumentCaptor<OpaRequestedResource> opaResource = ArgumentCaptor.forClass(OpaRequestedResource.class);
        verify(opaClient, times(2)).checkResourceAccess(any(), opaResource.capture(), any(), any());
        OpaRequestedResource parentCheck = opaResource.getAllValues().get(0);
        OpaRequestedResource childCheck = opaResource.getAllValues().get(1);
        assertThat(parentCheck.getProperties()).containsEntry("name", Resource.TOKEN_PROFILE.getCode());
        assertThat(parentCheck.getObjectUUIDs()).containsExactly(request.parentUuids().getFirst().toString());
        assertThat(childCheck.getProperties())
                .containsEntry("name", Resource.TOKEN.getCode())
                .containsEntry("action", ResourceAction.DETAIL.getCode());
        assertThat(childCheck.getObjectUUIDs()).containsExactly(request.objectUuids().getFirst().toString());
    }

    @Test
    void deniesWhenParentUuidGetterSpecifiedButNoObjectUuids() {
        // given: a ParentUUIDGetter is declared but the request carries no object UUIDs to resolve parents from
        AuthorizationRequest request = new AuthorizationRequest(
                Map.of("action", ResourceAction.DETAIL.getCode(), "name", Resource.TOKEN.getCode(),
                        "parentAction", ResourceAction.NONE.getCode(), "parentName", Resource.NONE.getCode()),
                List.of(),
                List.of(),
                false,
                Optional.of(staticParentUuidGetterClass()),
                "tokens:detail");

        // when
        AuthorizationDecision decision = core.decide(platformAuthentication(UUID.randomUUID().toString()), request);

        // then: denied before any OPA call is made
        assertThat(decision.isGranted()).isFalse();
        verifyNoInteractions(opaClient);
    }

    /** A child TOKEN:DETAIL check nested under a parent TOKEN_PROFILE:DETAIL check. */
    private AuthorizationRequest requestWithParent(List<SecuredUUID> objectUuids, List<SecuredUUID> parentUuids) {
        return new AuthorizationRequest(
                Map.of("action", ResourceAction.DETAIL.getCode(), "name", Resource.TOKEN.getCode(),
                        "parentAction", ResourceAction.DETAIL.getCode(), "parentName", Resource.TOKEN_PROFILE.getCode()),
                objectUuids,
                parentUuids,
                false,
                Optional.empty(),
                "tokens:detail");
    }

    @SuppressWarnings("unchecked")
    private static Class<ParentUUIDGetter> staticParentUuidGetterClass() {
        return (Class<ParentUUIDGetter>) (Class<?>) StaticParentUUIDGetter.class;
    }

    public static class StaticParentUUIDGetter implements ParentUUIDGetter {
        @Override
        public List<String> getParentsUUID(List<String> objectsUUID) {
            return List.of();
        }
    }

    /** A direct-check request for CERTIFICATE (has owner + groups) whose owner association never matches. */
    private AuthorizationRequest directCheckWithNonMatchingOwner() {
        SecuredUUID objectUuid = SecuredUUID.fromUUID(UUID.randomUUID());
        when(ownerAssociationRepository.countByOwnerUuidAndResourceAndObjectUuidIn(any(), eq(Resource.CERTIFICATE), any()))
                .thenReturn(0L);
        return AuthorizationRequest.forDirectCheck(Resource.CERTIFICATE, ResourceAction.DETAIL, List.of(objectUuid));
    }

    private OpaResourceAccessResult accessGranted() {
        OpaResourceAccessResult result = new OpaResourceAccessResult();
        result.setAuthorized(true);
        result.setAllow(List.of());
        return result;
    }

    private PlatformAuthenticationToken platformAuthentication(String userUuid) {
        return new PlatformAuthenticationToken(
                new PlatformUserDetails(
                        new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid, "FrantisekJednicka", List.of())
                )
        );
    }
}

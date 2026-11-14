package com.otilm.core.integration.security.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiReadInvocation;
import com.otilm.core.security.ai.AiReadInvocationContext;
import com.otilm.core.security.ai.CertificateReadScope;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.PlatformAuthenticationCache;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authn.client.TokenJtiIndex;
import com.otilm.core.security.authn.client.UserCertificateIndex;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.PlatformAuthorizationCache;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.handler.StoredCertificateHealth;
import com.otilm.core.util.SqlCapture;
import com.otilm.core.util.ai.AuthoritativePolicyProofSupport;
import com.otilm.core.util.ai.CertificateReadProofAdapter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.SoftAssertions;
import org.hibernate.Session;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.postgresql.util.PSQLException;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.AopTestUtils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verifyNoInteractions;

/** Ordinary-path characterization. Opt-in secure expectations expose known ordinary-path gaps. */
@SpringBootTest
class AiCertificateReadProofITest extends AuthoritativePolicyProofSupport {
    private static final UUID ACTOR = UUID.fromString("a1000000-0000-0000-0000-000000000001");
    private static final UUID OTHER = UUID.fromString("a2000000-0000-0000-0000-000000000002");
    private static final boolean SECURE_EXPECTATIONS = Boolean.getBoolean("ai.proof.secure-expectations");
    private static final Duration INVOCATION_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration AUTHORITY_TIMEOUT = Duration.ofMillis(300);
    private CertificateReadScope readScope;
    private OpaRequestedResource certificateListRequest;

    @Autowired
    private CertificateExternalService service;
    @Autowired
    private AiReadInvocation invocation;
    @Autowired
    private CertificateRepository certificates;
    @Autowired
    private RaProfileRepository profiles;
    @Autowired
    private GroupRepository groups;
    @Autowired
    private GroupAssociationRepository groupAssociations;
    @Autowired
    private OwnerAssociationRepository owners;
    @Autowired
    private AuthenticationCache authenticationCache;
    @Autowired
    private OpaClient opaClient;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private EventProducer eventProducer;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private PlatformTransactionManager transactions;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private AuditLogInternalService auditLogService;

    @Autowired
    private org.springframework.context.ApplicationEventPublisher proofEvents;
    @Autowired
    private com.otilm.core.client.ConnectorApiFactory connectorCalls;
    @Autowired
    private com.otilm.core.messaging.jms.producers.ValidationProducer validationProducer;
    @Autowired
    private com.otilm.core.messaging.jms.producers.NotificationProducer notificationProducer;
    @Autowired
    private com.otilm.core.messaging.jms.producers.ActionProducer actionProducer;
    @Autowired
    private com.otilm.core.util.mockbeans.ProducerMocks.RecordedNotificationMessages recordedMessages;

    private RaProfile profile;
    private RaProfile foreignProfile;
    private Certificate allowed;
    private Certificate conflict;
    private Certificate foreign;
    private Certificate owned;
    private Certificate grouped;
    private Group group;

    @BeforeEach
    void seedOutsideObservations() throws Exception {
        AUTHORITY.reset();
        authenticationCache.evictAll();
        authorizationCache.evictAll();
        jdbc
                .execute("TRUNCATE core.certificate, core.ra_profile, core.owner_association, "
                        + "core.group_association, core.\"group\" CASCADE");
        profile = profile("Synthetic profile A");
        foreignProfile = profile("Synthetic profile B");
        allowed = certificate(profile, "allowed.synthetic");
        conflict = certificate(profile, "conflict.synthetic");
        foreign = certificate(foreignProfile, "foreign.synthetic");
        owned = certificate(profile, "owned.synthetic");
        grouped = certificate(profile, "grouped.synthetic");
        OwnerAssociation owner = new OwnerAssociation();
        owner.setOwnerUuid(ACTOR);
        owner.setOwnerUsername("synthetic-" + ACTOR);
        owner.setResource(Resource.CERTIFICATE);
        owner.setObjectUuid(owned.getUuid());
        owners.saveAndFlush(owner);
        group = new Group();
        group.setName("Synthetic group");
        group = groups.saveAndFlush(group);
        GroupAssociation association = new GroupAssociation();
        association.setResource(Resource.CERTIFICATE);
        association.setObjectUuid(grouped.getUuid());
        association.setGroupUuid(group.getUuid());
        groupAssociations.saveAndFlush(association);
        clearInvocations(eventProducer);
        readScope = new CertificateReadScope(profile.getUuid(), Set.of(allowed.getUuid()));
        certificateListRequest = new OpaRequestedResource(Map.of("name", "certificates", "action", "list"));
    }

    @Test
    void positiveControlUsesRealProxiesPolicyHttpAndProtectedSql() throws Exception {
        assertThat(AopUtils.isAopProxy(service)).isTrue();
        assertThat(mockingDetails(opaClient).isMock()).isFalse();
        assertThat(mockingDetails(authenticationClient).isMock()).isFalse();
        assertThat(mockingDetails(certificates).isMock()).isFalse();
        assertThat(mockingDetails(eventProducer).isMock()).isTrue();
        Object serviceTarget = AopTestUtils.getUltimateTargetObject(service);
        assertThat(ReflectionTestUtils.getField(serviceTarget, "eventProducer")).isSameAs(eventProducer);
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        SqlCapture.Captured<List<UUID>> result = SqlCapture.during(this::list);
        assertThat(result.result()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        assertThat(protectedSql(result.statements())).hasSize(3);
        assertThat(AUTHORITY.count("/auth")).isEqualTo(1);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(3);
        assertThat(AUTHORITY.exchanges).allSatisfy(exchange -> assertThat(exchange.status()).isEqualTo(200));
        assertThat(AUTHORITY.exchanges.getFirst().request().path("userUuid").asText()).isEqualTo(ACTOR.toString());
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method"))
                .map(e -> e.request().at("/input/requestedResource/name").asText()))
                .containsExactly("raProfiles", "certificates");
        System.out
                .println("[AI-PROOF] positive: Auth=1 method=2 objects=3 certificateSQL=3; PostgreSQL="
                        + jdbc.queryForObject("SHOW server_version", String.class));
        var bindings = fixturePortBindings();
        System.out.println("[AI-PROOF] actual Docker port bindings: " + bindings);
        assertThat(bindings).containsOnlyKeys("opa", "postgres");
        bindings
                .forEach((name, ports) -> assertThat(ports)
                        .as(name + " Docker published ports")
                        .isNotEmpty()
                        .allSatisfy(binding -> {
                            assertThat(binding.getHostIp()).isEqualTo("127.0.0.1");
                            assertThat(Integer.parseInt(binding.getHostPortSpec())).isBetween(1, 65535);
                        }));
        verifyNoInteractions(eventProducer);
    }

    @Test
    void disjointPrincipalGetsOnlyItsActualPolicyIntersection() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        assertThat(list()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        authenticate(OTHER, principal(OTHER, foreignProfile, List.of(foreign.getUuid()), List.of(), List.of()));
        assertThat(list()).containsExactly(foreign.getUuid());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(4);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(6);
    }

    @Test
    void warmMethodAndObjectAllowsSurviveOpaOutage() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        assertThat(list()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        AUTHORITY.exchanges.clear();
        AUTHORITY.opaUnavailable = true;
        SqlCapture.Captured<List<UUID>> result = SqlCapture.during(this::list);
        assertThat(AUTHORITY.exchanges).isEmpty();
        assertThat(protectedSql(result.statements())).hasSize(3);
        assertThat(result.result()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        authorizationCache.evictAll();
        SqlCapture.Captured<Boolean> cold = SqlCapture.during(() -> {
            assertThatThrownBy(this::list)
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessage("An error occurred when calling OPA.");
            return true;
        });
        assertThat(AUTHORITY.exchanges).isNotEmpty().allSatisfy(e -> assertThat(e.status()).isEqualTo(503));
        assertThat(protectedSql(cold.statements())).isEmpty();
        verifyNoInteractions(eventProducer);
        if (SECURE_EXPECTATIONS) {
            assertThat(result.result())
                    .as("secure expectation: an unavailable authority must prevent the read")
                    .isEmpty();
        }
    }

    @Test
    void warmUserUuidPrincipalSurvivesAnonymousAuthAuthority() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        assertThat(list()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        AUTHORITY.exchanges.clear();
        AUTHORITY.anonymous = true;
        authenticateCachedActor();
        SqlCapture.Captured<List<UUID>> result = SqlCapture.during(this::list);
        assertThat(AUTHORITY.exchanges).isEmpty();
        assertThat(result.result()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        assertThat(protectedSql(result.statements())).hasSize(3);
        assertThat(authenticationClient
                .authenticate(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY, ACTOR, false)
                .isAnonymous()).isTrue();
        assertThat(AUTHORITY.count("/auth")).isEqualTo(1);
        if (SECURE_EXPECTATIONS) {
            assertThat(result.result()).as("secure expectation: changed Auth identity must stop the read").isEmpty();
        }
    }

    @Test
    void restrictedPolicyReturnsAllowDenyOverlapAndLegacyListingIncludesIt() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid(), conflict.getUuid()),
                List.of(conflict.getUuid()), List.of()));
        SecurityFilter filter = SecurityFilter.create();
        SqlCapture.Captured<List<UUID>> result = SqlCapture
                .during(() -> service
                        .listCertificates(filter, new CertificateSearchRequestDto())
                        .getCertificates()
                        .stream()
                        .map(c -> UUID.fromString(c.getUuid()))
                        .toList());
        assertThat(filter.getResourceFilter().areOnlySpecificObjectsAllowed()).isTrue();
        assertThat(filter.getResourceFilter().getAllowedObjects()).contains(conflict.getUuid());
        assertThat(filter.getResourceFilter().getForbiddenObjects()).contains(conflict.getUuid());
        assertThat(result.result()).containsExactlyInAnyOrder(allowed.getUuid(), conflict.getUuid(), owned.getUuid());
        assertThat(protectedSql(result.statements())).hasSize(3);
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/objects"))
                .filter(e -> e.request().at("/input/requestedResource/name").asText().equals("certificates")))
                .singleElement()
                .satisfies(e -> {
                    assertThat(e.response().at("/result/allowedObjects").toString())
                            .contains(conflict.getUuid().toString());
                    assertThat(e.response().at("/result/forbiddenObjects").toString())
                            .contains(conflict.getUuid().toString());
                });
        if (SECURE_EXPECTATIONS) {
            assertThat(result.result())
                    .as("secure expectation: explicit deny must win")
                    .doesNotContain(conflict.getUuid());
        }
    }

    @Test
    void validationGetterDirtiesManagedRowAndLaterOsivTransactionPersistsIt() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        var beforeRows = completeBusinessSnapshot();
        EntityManager em = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(em));
        SqlCapture.Captured<CertificateValidationStatus> getter;
        SqlCapture.Captured<Void> flush;
        boolean dirty;
        try {
            getter = SqlCapture
                    .during(() -> service
                            .getCertificateValidationResult(SecuredUUID.fromUUID(allowed.getUuid()))
                            .getResultStatus());
            assertThat(getter.result()).isEqualTo(CertificateValidationStatus.NOT_CHECKED);
            assertThat(getter.statements()).noneMatch(sql -> sql.startsWith("update core.certificate "));
            dirty = em.unwrap(Session.class).isDirty();
            assertThat(dirty).isTrue();
            assertThat(storedValidationStatus()).isEqualTo("VALID");
            // The write depends on a later transaction sharing the request's managed EntityManager.
            flush = SqlCapture.during(() -> {
                new TransactionTemplate(transactions).executeWithoutResult(status -> em.flush());
                return null;
            });
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            em.close();
        }
        assertThat(flush.statements()).anyMatch(sql -> sql.startsWith("update core.certificate "));
        assertThat(storedValidationStatus()).isEqualTo("NOT_CHECKED");
        boolean rowsUnchanged = completeBusinessSnapshot().equals(beforeRows);
        assertThat(rowsUnchanged).as("complete rows detect the later getter write").isFalse();
        verifyNoInteractions(eventProducer);
        if (SECURE_EXPECTATIONS) {
            assertThat(dirty).as("secure expectation: a stored-health read cannot leave a managed row dirty").isFalse();
        }
    }

    @Test
    void changedRawPermissionsStayStaleUntilDirectAuthThenUseNewOpaCacheKey() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        assertThat(list()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        AUTHORITY.principal = principal(ACTOR, foreignProfile, List.of(foreign.getUuid()), List.of(), List.of());
        AUTHORITY.exchanges.clear();
        authenticateCachedActor();
        assertThat(list()).containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
        assertThat(AUTHORITY.exchanges).isEmpty();
        var fresh = authenticationClient
                .authenticate(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY, ACTOR, false);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(fresh)));
        assertThat(list()).containsExactlyInAnyOrder(foreign.getUuid(), owned.getUuid());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(1);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(3);
    }

    @Test
    void ownedObjectSurvivesColdOpaFailureButUnownedObjectStopsBeforeCertificateSql() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(), List.of(), List.of()));
        AUTHORITY.exchanges.clear();
        AUTHORITY.opaUnavailable = true;
        SqlCapture.Captured<CertificateValidationStatus> result = SqlCapture
                .during(() -> service
                        .getCertificateValidationResult(SecuredUUID.fromUUID(owned.getUuid()))
                        .getResultStatus());
        assertThat(result.result()).isEqualTo(CertificateValidationStatus.NOT_CHECKED);
        assertThat(protectedSql(result.statements())).hasSize(1);
        assertThat(result.statements()).anyMatch(sql -> sql.contains("from core.owner_association "));
        assertThat(AUTHORITY.exchanges).hasSize(2).allSatisfy(e -> {
            assertThat(e.path()).isEqualTo("/v1/data/method");
            assertThat(e.status()).isEqualTo(503);
        });
        SqlCapture.Captured<Boolean> denied = SqlCapture.during(() -> {
            assertThatThrownBy(() -> service.getCertificateValidationResult(SecuredUUID.fromUUID(allowed.getUuid())))
                    .isInstanceOf(org.springframework.security.authorization.AuthorizationDeniedException.class);
            return true;
        });
        assertThat(protectedSql(denied.statements())).isEmpty();
        verifyNoInteractions(eventProducer);
        if (SECURE_EXPECTATIONS) {
            assertThat(protectedSql(result.statements()))
                    .as("secure expectation: OPA failure cannot use owner fallback")
                    .isEmpty();
        }
    }

    @Test
    void genuineGroupMembershipGrantAddsGroupedCertificate() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of(group.getUuid())));
        SqlCapture.Captured<List<UUID>> result = SqlCapture.during(this::list);
        assertThat(result.result()).containsExactlyInAnyOrder(allowed.getUuid(), grouped.getUuid(), owned.getUuid());
        assertThat(protectedSql(result.statements())).hasSize(3);
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/objects"))
                .filter(e -> e.request().at("/input/requestedResource/name").asText().equals("groups")))
                .singleElement()
                .satisfies(e -> assertThat(e.response().at("/result/allowedObjects").toString())
                        .contains(group.getUuid().toString()));
    }

    @Test
    void genuineMethodPolicyDenyPreventsUnownedDetailSql() throws Exception {
        authenticate(OTHER,
                principal(OTHER, profile, List.of(allowed.getUuid()), List.of(allowed.getUuid()), List.of()));
        SqlCapture.Captured<Boolean> result = SqlCapture.during(() -> {
            assertThatThrownBy(() -> service.getCertificateValidationResult(SecuredUUID.fromUUID(allowed.getUuid())))
                    .isInstanceOf(org.springframework.security.authorization.AuthorizationDeniedException.class);
            return true;
        });
        assertThat(protectedSql(result.statements())).isEmpty();
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method"))
                .filter(e -> e.request().at("/input/requestedResource/name").asText().equals("certificates")))
                .singleElement()
                .satisfies(e -> {
                    assertThat(e.response().at("/result/authorized").asBoolean()).isFalse();
                    assertThat(e.response().at("/result/allow").isEmpty()).isFalse();
                    assertThat(e.response().at("/result/deny").toString()).contains("ActionDeniedForSpecificObject");
                });
        verifyNoInteractions(eventProducer);
    }

    private static SimpleCacheManager independentCacheManager() {
        SimpleCacheManager manager = new SimpleCacheManager();
        manager
                .setCaches(List
                        .of(CacheConfig.SYSTEM_USER_AUTH_CACHE, CacheConfig.USER_UUID_AUTH_CACHE,
                                CacheConfig.CERTIFICATE_AUTH_CACHE, CacheConfig.TOKEN_AUTH_CACHE,
                                CacheConfig.RESOURCE_AUTHZ_CACHE, CacheConfig.OBJECT_AUTHZ_CACHE)
                        .stream()
                        .map(name -> new ReadThroughCache(name, Caffeine.newBuilder().maximumSize(100).buildAsync()))
                        .toList());
        manager.initializeCaches();
        return manager;
    }

    @Test
    void independentCacheInstancesRetainTheirOwnWarmAllows() throws Exception {
        // Independent instances share actual HTTP authorities; TTL and capacity behavior are outside this test.
        SimpleCacheManager manager = independentCacheManager();
        AuthenticationCache secondAuthenticationCache = new PlatformAuthenticationCache(manager, new TokenJtiIndex(),
                new UserCertificateIndex());
        var secondAuthenticationClient = new PlatformAuthenticationClient(auditLogService, objectMapper,
                secondAuthenticationCache, AUTHORITY.url());
        var secondAuthorizationCache = new PlatformAuthorizationCache(manager, objectMapper,
                new AuthorizationCacheProperties(true, 5, 10000, 1000));
        OpaClient secondOpa = new OpaClient(objectMapper, AUTHORITY.url(), secondAuthorizationCache);
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        var first = authenticationClient.authenticateByUserUuid(ACTOR);
        var second = secondAuthenticationClient.authenticateByUserUuid(ACTOR);
        String firstPrincipal = first.getRawData();
        String secondPrincipal = second.getRawData();
        OpaRequestedResource request = new OpaRequestedResource(Map.of("name", "certificates", "action", "list"));
        var details = new OpaRequestDetails(null);
        assertMethodAndObjectGrant(opaClient, firstPrincipal, request, details);
        assertMethodAndObjectGrant(secondOpa, secondPrincipal, request, details);
        assertThat(AUTHORITY.count("/auth")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(2);
        AUTHORITY.anonymous = true;
        AUTHORITY.opaUnavailable = true;
        AUTHORITY.exchanges.clear();
        assertThat(authenticationClient.authenticateByUserUuid(ACTOR).isAnonymous()).isFalse();
        assertThat(secondAuthenticationClient.authenticateByUserUuid(ACTOR).isAnonymous()).isFalse();
        assertMethodAndObjectGrant(opaClient, firstPrincipal, request, details);
        assertMethodAndObjectGrant(secondOpa, secondPrincipal, request, details);
        assertThat(AUTHORITY.exchanges).isEmpty();
        secondAuthenticationCache.evictAll();
        secondAuthorizationCache.evictAll();
        assertThat(secondAuthenticationClient.authenticateByUserUuid(ACTOR).isAnonymous()).isTrue();
        assertThatThrownBy(() -> secondOpa.checkResourceAccess("method", request, secondPrincipal, details))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("An error occurred when calling OPA.");
        assertThat(AUTHORITY.count("/auth")).isEqualTo(1);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(1);
        assertThat(authenticationClient.authenticateByUserUuid(ACTOR).isAnonymous()).isFalse();
        assertThat(opaClient.checkResourceAccess("method", request, firstPrincipal, details).isAuthorized()).isTrue();
        assertThat(AUTHORITY.exchanges).hasSize(2);
    }

    @Test
    void parentDenialInLegacyGetterOccursAfterCertificateRead() throws Exception {
        authenticate(OTHER, principal(OTHER, foreignProfile, List.of(allowed.getUuid()), List.of(), List.of()));
        SqlCapture.Captured<Boolean> result = SqlCapture.during(() -> {
            assertThatThrownBy(() -> service.getCertificateValidationResult(SecuredUUID.fromUUID(allowed.getUuid())))
                    .isInstanceOf(org.springframework.security.authorization.AuthorizationDeniedException.class);
            return true;
        });
        assertThat(protectedSql(result.statements())).hasSize(1);
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method"))
                .map(e -> e.request().at("/input/requestedResource/name").asText()))
                .containsExactly("certificates", "raProfiles");
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method"))
                .filter(e -> e.request().at("/input/requestedResource/name").asText().equals("raProfiles")))
                .singleElement()
                .satisfies(e -> assertThat(e.response().at("/result/authorized").asBoolean()).isFalse());
        verifyNoInteractions(eventProducer);
        if (SECURE_EXPECTATIONS) {
            assertThat(protectedSql(result.statements()))
                    .as("secure expectation: parent denial precedes certificate SQL")
                    .isEmpty();
        }
    }

    @Test
    void actualAuthHttpClientObservesChangedActorAndRecordedErrorFixtures() throws Exception {
        AUTHORITY.principal = principal(OTHER, foreignProfile, List.of(foreign.getUuid()), List.of(), List.of());
        var changedActor = authenticationClient
                .authenticate(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY, ACTOR, false);
        assertThat(changedActor.getUserUuid()).isEqualTo(OTHER.toString());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(1);
        assertThat(AUTHORITY.exchanges.getFirst().request().path("userUuid").asText()).isEqualTo(ACTOR.toString());
        AUTHORITY.authStatus = 500;
        SqlCapture.Captured<Boolean> result = SqlCapture.during(() -> {
            assertThatThrownBy(() -> authenticationClient
                    .authenticate(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY, ACTOR, false))
                    .isInstanceOf(com.otilm.core.security.authn.PlatformAuthenticationException.class)
                    .hasMessage("Internal Server Error from Auth Service");
            return true;
        });
        assertThat(AUTHORITY.count("/auth")).isEqualTo(2);
        assertThat(AUTHORITY.exchanges.getLast().status()).isEqualTo(500);
        assertThat(protectedSql(result.statements())).isEmpty();
        AUTHORITY.reset();
        assertThat(AUTHORITY.principal).as("a reset authority must not reuse another test's principal").isNull();
        assertThatThrownBy(() -> authenticationClient
                .authenticate(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY, ACTOR, false))
                .isInstanceOf(com.otilm.core.security.authn.PlatformAuthenticationException.class)
                .hasMessage("Internal Server Error from Auth Service");
        assertThat(AUTHORITY.exchanges).singleElement().satisfies(exchange -> {
            assertThat(exchange.path()).isEqualTo("/auth");
            assertThat(exchange.status()).isEqualTo(500);
            assertThat(exchange.response().path("message").asText()).isEqualTo("Synthetic authority fixture failure");
        });
        verifyNoInteractions(eventProducer);
    }

    @Test
    void refreshesAuthRawDataAtActualMethodVote() throws Exception {
        assertRevocationAtVote(2, false);
    }

    @Test
    void refreshesAuthRawDataAtActualObjectVote() throws Exception {
        assertRevocationAtVote(4, true);
    }

    private void assertRevocationAtVote(int selectedAuth, boolean objectVote) throws Exception {
        String initial = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        String revoked = principal(ACTOR, profile, List.of(), List.of(), List.of());
        authenticate(ACTOR, initial);
        list();
        AUTHORITY.exchanges.clear();
        SqlCapture.Captured<Boolean> captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                assertThat(
                        opaClient.checkResourceAccess("method", certificateListRequest, initial, null).isAuthorized())
                        .isTrue();
                AtomicInteger actualAuth = new AtomicInteger();
                AUTHORITY.beforeRequest = (path, body) -> {
                    if (path.equals("/auth") && actualAuth.incrementAndGet() == selectedAuth) {
                        AUTHORITY.principal = revoked;
                    }
                };
                return list();
            })).isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(selectedAuth + 2L);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(3);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(objectVote ? 2 : 0);
        var vote = AUTHORITY.exchanges.getLast();
        assertThat(vote.request().at("/input/principal")).isEqualTo(JSON.readTree(revoked));
        assertThat(vote.request().at("/input/principal/user/uuid").asText()).isEqualTo(ACTOR.toString());
        if (objectVote) {
            assertThat(vote.response().at("/result/allowedObjects")).isEmpty();
        } else {
            assertThat(vote.response().at("/result/authorized").asBoolean()).isFalse();
        }
        assertThat(AiReadInvocationContext.isActive()).isFalse();
        verifyNoInteractions(eventProducer);
        System.out
                .println("[AI-PROOF] fresh " + (objectVote ? "object" : "method") + " denial: Auth="
                        + AUTHORITY.count("/auth") + " method=3 objects=" + AUTHORITY.count("/v1/data/objects")
                        + " protectedSQL=0 associationSQL=0");
    }

    @Test
    void warmResourceAllowCannotHideAuthorityOutage() throws Exception {
        scopedWarmCacheOutageAtVote(1);
    }

    @Test
    void warmObjectAllowCannotHideAuthorityOutage() throws Exception {
        scopedWarmCacheOutageAtVote(3);
    }

    private void scopedWarmCacheOutageAtVote(int selectedAuth) throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        list();
        AUTHORITY.exchanges.clear();
        SqlCapture.Captured<Boolean> captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                AtomicInteger actualAuth = new AtomicInteger();
                AUTHORITY.beforeRequest = (path, body) -> {
                    if (path.equals("/auth") && actualAuth.incrementAndGet() == selectedAuth) {
                        AUTHORITY.opaUnavailable = true;
                    }
                };
                return list();
            })).isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(selectedAuth + 1L);
        assertThat(AUTHORITY.exchanges.getLast().status()).isEqualTo(503);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(selectedAuth == 1 ? 1 : 2);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(selectedAuth == 1 ? 0 : 1);
        verifyNoInteractions(eventProducer);
    }

    @Test
    void anonymousCrossActorOrMalformedAuthorityCannotReachProtectedSql() throws Exception {
        String initial = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        String other = principal(OTHER, profile, List.of(allowed.getUuid()), List.of(), List.of());
        for (String changed : List
                .of("{\"authenticated\":false}", "{\"authenticated\":true,\"data\":" + other + "}",
                        "{\"authenticated\":true,\"data\":null}")) {
            AUTHORITY.reset();
            AUTHORITY.principal = initial;
            var captured = SqlCapture.during(() -> {
                assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                    assertThat(opaClient
                            .checkResourceAccess("method", certificateListRequest, initial, null)
                            .isAuthorized()).isTrue();
                    AUTHORITY.authResponseOverride = changed;
                    return list();
                })).isInstanceOf(AccessDeniedException.class);
                return true;
            });
            assertNoProtectedOrAssociationSql(captured.statements());
            assertThat(AUTHORITY.count("/auth")).isEqualTo(3);
            assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(1);
            assertThat(AUTHORITY.count("/v1/data/objects")).isZero();
        }
        verifyNoInteractions(eventProducer);
    }

    @Test
    void disabledActorAtActualMethodVoteCannotReachProtectedSql() throws Exception {
        assertRejectedActorAtVote(2, false);
    }

    @Test
    void disabledActorAtActualObjectVoteCannotReachProtectedSql() throws Exception {
        assertRejectedActorAtVote(4, false);
    }

    @Test
    void anonymousActorAtActualObjectVoteCannotReachProtectedSql() throws Exception {
        assertRejectedActorAtVote(4, true);
    }

    private void assertRejectedActorAtVote(int selectedAuth, boolean anonymous) throws Exception {
        String initial = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        var disabled = (ObjectNode) JSON.readTree(initial);
        ((ObjectNode) disabled.path("user")).put("enabled", false);
        String response = anonymous
                ? "{\"authenticated\":false}"
                : "{\"authenticated\":true,\"data\":" + disabled + "}";
        authenticate(ACTOR, initial);
        list();
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                assertThat(
                        opaClient.checkResourceAccess("method", certificateListRequest, initial, null).isAuthorized())
                        .isTrue();
                AtomicInteger actualAuth = new AtomicInteger();
                AUTHORITY.beforeRequest = (path, body) -> {
                    if (path.equals("/auth") && actualAuth.incrementAndGet() == selectedAuth) {
                        AUTHORITY.authResponseOverride = response;
                    }
                };
                return list();
            })).isInstanceOf(AccessDeniedException.class).hasNoCause();
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(selectedAuth + 2L);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(selectedAuth == 2 ? 2 : 3);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(selectedAuth == 2 ? 0 : 1);
        var rejected = AUTHORITY.exchanges.getLast();
        assertThat(rejected.path()).isEqualTo("/auth");
        assertThat(rejected.response()).isEqualTo(JSON.readTree(response));
        assertThat(AiReadInvocationContext.isActive()).isFalse();
        verifyNoInteractions(eventProducer);
        System.out
                .println("[AI-PROOF] " + (anonymous ? "anonymous" : "disabled") + " at "
                        + (selectedAuth == 2 ? "method" : "object") + ": Auth=" + AUTHORITY.count("/auth") + " method="
                        + AUTHORITY.count("/v1/data/method") + " objects=" + AUTHORITY.count("/v1/data/objects")
                        + " protectedSQL=0 associationSQL=0");
    }

    @Test
    void malformedPolicyEvidenceCannotReachProtectedSql() throws Exception {
        for (String malformed : List
                .of("{\"result\":null}", "{}", "{\"result\":{\"authorized\":true,\"allow\":[],\"deny\":[]}}")) {
            AUTHORITY.reset();
            AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
            var captured = SqlCapture.during(() -> {
                assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                    AUTHORITY.malformedOpaResponse = malformed;
                    return list();
                })).isInstanceOf(AccessDeniedException.class);
                return true;
            });
            assertNoProtectedOrAssociationSql(captured.statements());
            assertThat(AUTHORITY.count("/auth")).isEqualTo(2);
            assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(1);
        }
        verifyNoInteractions(eventProducer);
    }

    @Test
    void realPolicyDenyUpdateInvalidatesWarmGrantAndRestoresPinnedBytes() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        Map<String, String> before = AUTHORITY.runningPolicyHashes();
        assertPinnedPolicyHashes(before);
        try {
            var captured = SqlCapture.during(() -> {
                assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                    assertThat(opaClient
                            .checkResourceAccess("method", certificateListRequest, AUTHORITY.principal, null)
                            .isAuthorized()).isTrue();
                    AUTHORITY.installTestMethodDeny();
                    return list();
                })).isInstanceOf(AccessDeniedException.class);
                return true;
            });
            assertNoProtectedOrAssociationSql(captured.statements());
            var denied = AUTHORITY.exchanges.getLast();
            assertThat(denied.response().at("/result/authorized").asBoolean()).isFalse();
            assertThat(denied.response().at("/result/deny").toString()).contains("SyntheticFaultInjection");
        } finally {
            AUTHORITY.removeTestMethodDeny();
            assertThat(AUTHORITY.runningPolicyHashes()).isEqualTo(before);
        }
        invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
            assertThat(opaClient
                    .checkResourceAccess("method", certificateListRequest, AUTHORITY.principal, null)
                    .isAuthorized()).isTrue();
            return null;
        });
        verifyNoInteractions(eventProducer);
    }

    @Test
    void realObjectPolicyDenyAtActualVoteRestoresPinnedBytes() throws Exception {
        String initial = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticate(ACTOR, initial);
        list();
        AUTHORITY.exchanges.clear();
        Map<String, String> before = AUTHORITY.runningPolicyHashes();
        assertPinnedPolicyHashes(before);
        var original = AUTHORITY.objectPolicySource();
        var installed = new AtomicBoolean();
        try {
            var captured = SqlCapture.during(() -> {
                assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                    assertThat(opaClient
                            .checkResourceAccess("method", certificateListRequest, initial, null)
                            .isAuthorized()).isTrue();
                    assertThat(opaClient
                            .checkObjectAccess("objects", certificateListRequest, initial, null)
                            .getAllowedObjects()).contains(allowed.getUuid().toString());
                    AUTHORITY.beforeRequest = (path, body) -> {
                        if (path.equals("/v1/data/objects")
                                && body.at("/input/requestedResource/name").asText().equals("certificates")) {
                            try {
                                AUTHORITY.installTestObjectDeny(original, allowed.getUuid());
                                installed.set(true);
                            } catch (Exception failure) {
                                throw new IllegalStateException("Disposable object deny update failed", failure);
                            }
                        }
                    };
                    return list();
                })).isInstanceOf(AccessDeniedException.class).hasNoCause();
                return true;
            });
            assertThat(installed).isTrue();
            assertNoProtectedOrAssociationSql(captured.statements());
            var denied = AUTHORITY.exchanges.getLast();
            assertThat(denied.path()).isEqualTo("/v1/data/objects");
            assertThat(denied.status()).isEqualTo(200);
            assertThat(denied.response().at("/result/actionAllowedForGroupOfObjects").isBoolean()).isTrue();
            assertThat(denied.response().at("/result/actionAllowedForGroupOfObjects").booleanValue()).isFalse();
            assertThat(denied.response().at("/result/allowedObjects").isArray()).isTrue();
            assertThat(denied.response().at("/result/allowedObjects")).isEmpty();
            assertThat(denied.response().at("/result/forbiddenObjects").isArray()).isTrue();
            assertThat(denied.response().at("/result/forbiddenObjects")).hasToString("[\"" + allowed.getUuid() + "\"]");
            assertThat(AUTHORITY.count("/auth")).isEqualTo(7);
            assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(3);
            assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(3);
            System.out
                    .println(
                            "[AI-PROOF] test-only object policy DENY: Auth=7 method=3 objects=3 protectedSQL=0 associationSQL=0");
        } finally {
            AUTHORITY.beforeRequest = null;
            AUTHORITY.restorePolicy(original);
            assertThat(AUTHORITY.runningPolicyHashes()).isEqualTo(before);
        }
        invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
            assertThat(
                    opaClient.checkObjectAccess("objects", certificateListRequest, initial, null).getAllowedObjects())
                    .contains(allowed.getUuid().toString());
            return null;
        });
        verifyNoInteractions(eventProducer);
    }

    private static void assertPinnedPolicyHashes(Map<String, String> hashes) {
        assertThat(hashes.values())
                .containsExactlyInAnyOrder("de316e802c527c0cf152b5ffa2b5757fa562ed2ed233e0f7589857b68349c175",
                        "e4a651b68159c2b3628c096032d4cadebd597303e769d51ec66e721cf79c9f11");
    }

    @Test
    void scopedAdministratorCannotCallValidationDownloadsOrWrites() throws Exception {
        var admin = (ObjectNode) JSON.readTree(principal(ACTOR, profile, List.of(), List.of(), List.of()));
        ((ObjectNode) admin.path("permissions")).put("allowAllResources", true);
        AUTHORITY.principal = admin.toString();
        var captured = SqlCapture.during(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
            for (org.junit.jupiter.api.function.ThrowingSupplier<?> blocked : List.<org.junit.jupiter.api.function.ThrowingSupplier<?>>of(
                    () -> service.getCertificateValidationResult(SecuredUUID.fromUUID(allowed.getUuid())),
                    () -> service.downloadCertificate(SecuredUUID.fromUUID(allowed.getUuid()), null, null),
                    () -> service.downloadCertificateChain(SecuredUUID.fromUUID(allowed.getUuid()), null, true, null),
                    () -> {
                        service.deleteCertificate(SecuredUUID.fromUUID(allowed.getUuid()));
                        return null;
                    }, () -> {
                        service.updateCertificateObjects(SecuredUUID.fromUUID(allowed.getUuid()), null);
                        return null;
                    })) {
                assertThatThrownBy(blocked::get).isInstanceOf(AccessDeniedException.class);
            }
            return true;
        }));
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(1);
        assertThat(AUTHORITY.count("/v1/data/method")).isZero();
        assertThat(AUTHORITY.count("/v1/data/objects")).isZero();
        verifyNoInteractions(eventProducer);
    }

    @Test
    void actualAuthAndOpaTimeoutsStopBeforeProtectedSql() throws Exception {
        for (boolean delayAuth : List.of(true, false)) {
            AUTHORITY.reset();
            AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
            var release = new java.util.concurrent.CountDownLatch(1);
            String targetPath = delayAuth ? "/auth" : "/v1/data/method";
            var targetReached = new AtomicBoolean();
            long started = System.nanoTime();
            try {
                var captured = SqlCapture.during(() -> {
                    assertThatThrownBy(() -> invocation.call(ACTOR, readScope, AUTHORITY_TIMEOUT, () -> {
                        AUTHORITY.beforeRequest = (path, ignored) -> {
                            if (targetPath.equals(path)) {
                                targetReached.set(true);
                            }
                        };
                        if (delayAuth) {
                            AUTHORITY.authResponseRelease = release;
                        } else {
                            AUTHORITY.opaResponseRelease = release;
                        }
                        return list();
                    })).isInstanceOf(AccessDeniedException.class);
                    return true;
                });
                assertThat(targetReached.get()).as("Blocked authority request reached %s", targetPath).isTrue();
                assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
                assertNoProtectedOrAssociationSql(captured.statements());
            } finally {
                release.countDown();
            }
            org.awaitility.Awaitility
                    .await()
                    .atMost(INVOCATION_TIMEOUT)
                    .untilAsserted(() -> assertThat(AUTHORITY.count(targetPath))
                            .as("Completed authority responses for %s", targetPath)
                            .isEqualTo(delayAuth ? 2 : 1));
            assertThat(AiReadInvocationContext.isActive()).isFalse();
        }
        verifyNoInteractions(eventProducer);
    }

    @Test
    void otherReplicaCacheCannotRestoreOldAuthority() throws Exception {
        SimpleCacheManager manager = independentCacheManager();
        AuthenticationCache cache = new PlatformAuthenticationCache(manager, new TokenJtiIndex(),
                new UserCertificateIndex());
        var otherAuth = new PlatformAuthenticationClient(auditLogService, objectMapper, cache, AUTHORITY.url());
        var otherOpa = new OpaClient(objectMapper, AUTHORITY.url(), new PlatformAuthorizationCache(manager,
                objectMapper, new AuthorizationCacheProperties(true, 5, 1000, 1000)));
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        String warm = otherAuth.authenticateByUserUuid(ACTOR).getRawData();
        assertThat(otherOpa.checkResourceAccess("method", certificateListRequest, warm, null).isAuthorized()).isTrue();
        assertThat(otherOpa.checkObjectAccess("objects", certificateListRequest, warm, null).getAllowedObjects())
                .contains(allowed.getUuid().toString());
        AUTHORITY.exchanges.clear();
        var reachedService = new AtomicBoolean();
        var otherInvocation = new AiReadInvocation(otherAuth);
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> otherInvocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                AUTHORITY.anonymous = true;
                otherOpa.checkResourceAccess("method", certificateListRequest, warm, null);
                reachedService.set(true);
                return list();
            })).isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertThat(reachedService).isFalse();
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/auth")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/method")).isZero();
        assertThat(otherAuth.authenticateByUserUuid(ACTOR).isAnonymous()).isFalse();
        assertThat(AUTHORITY.count("/auth")).isEqualTo(2);
        verifyNoInteractions(eventProducer);
    }

    @Test
    void cancellationDuringActualAuthorityTransportRestoresWorkerAndRunsNoSql() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        var entered = new java.util.concurrent.CountDownLatch(1);
        var exited = new java.util.concurrent.CountDownLatch(1);
        var cleaned = new AtomicBoolean();
        var statements = new AtomicReference<List<String>>();
        var release = new java.util.concurrent.CountDownLatch(1);
        AUTHORITY.opaResponseRelease = release;
        AUTHORITY.beforeRequest = (path, body) -> {
            if (path.equals("/v1/data/method")) {
                entered.countDown();
            }
        };
        try (var worker = Executors.newSingleThreadExecutor()) {
            var future = worker.submit(() -> {
                try {
                    var captured = SqlCapture.during(() -> {
                        assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::list))
                                .isInstanceOf(AccessDeniedException.class);
                        return true;
                    });
                    statements.set(captured.statements());
                } finally {
                    cleaned
                            .set(!AiReadInvocationContext.isActive()
                                    && SecurityContextHolder.getContext().getAuthentication() == null
                                    && org.slf4j.MDC.getCopyOfContextMap() == null
                                    && org.springframework.web.context.request.RequestContextHolder
                                            .getRequestAttributes() == null);
                    exited.countDown();
                }
                return null;
            });
            try {
                assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
                assertThat(future.cancel(true)).isTrue();
                assertThat(exited.await(2, TimeUnit.SECONDS)).isTrue();
                assertThat(worker
                        .submit(() -> !AiReadInvocationContext.isActive()
                                && SecurityContextHolder.getContext().getAuthentication() == null)
                        .get()).isTrue();
            } finally {
                release.countDown();
                future.cancel(true);
            }
        }
        assertThat(cleaned).isTrue();
        assertThat(statements.get()).isNotNull();
        assertNoProtectedOrAssociationSql(statements.get());
        org.awaitility.Awaitility
                .await()
                .atMost(INVOCATION_TIMEOUT)
                .until(() -> AUTHORITY.count("/v1/data/method") == 1);
        verifyNoInteractions(eventProducer);
    }

    @Test
    void actualAuthorityErrorBodiesCannotReachNamedLogsOrAuditProducer() throws Exception {
        String canary = "synthetic-forbidden-authority-body-canary";
        List<String> loggerNames = List
                .of("com.otilm.core.security.authn.client.PlatformAuthenticationClient",
                        "com.otilm.core.security.authn.client.PlatformBaseAuthenticationClient",
                        "com.otilm.core.security.authz.opa.OpaClient",
                        "com.otilm.core.security.authz.ExternalAuthorizationCore",
                        "com.otilm.core.service.impl.AuditLogServiceImpl",
                        "com.otilm.core.messaging.jms.producers.AuditLogsProducer",
                        "com.otilm.core.service.impl.CertificateServiceImpl",
                        "com.otilm.core.service.handler.StoredCertificateHealthProjector",
                        "com.otilm.core.util.ai.CertificateReadProofAdapter");
        var appender = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        appender.start();
        var levels = new java.util.HashMap<ch.qos.logback.classic.Logger, ch.qos.logback.classic.Level>();
        for (String name : loggerNames) {
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(name);
            levels.put(logger, logger.getLevel());
            logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
            logger.addAppender(appender);
        }
        clearInvocations(auditLogsProducer);
        try {
            for (boolean authError : List.of(true, false)) {
                for (String route : List.of("list", "storedTool", "report")) {
                    AUTHORITY.reset();
                    AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
                    com.otilm.core.util.AuthHelper.ThrowingSupplier<Object, Exception> action = () -> {
                        if (authError) {
                            AUTHORITY.authStatus = 403;
                            AUTHORITY.authResponseOverride = JSON.createObjectNode().put("message", canary).toString();
                        } else {
                            AUTHORITY.opaUnavailable = true;
                            AUTHORITY.opaErrorMessage = canary;
                        }
                        return switch (route) {
                            case "storedTool" -> proofAdapter()
                                    .dispatch(
                                            "{\"tool\":\"certificate.storedHealth\",\"arguments\":{\"certificateUuid\":\""
                                                    + allowed.getUuid() + "\"}}");
                            case "report" -> proofAdapter()
                                    .report(new CertificateReadProofAdapter.SearchArguments(1, 10, null, null, null));
                            default -> list();
                        };
                    };
                    var captured = SqlCapture.during(() -> {
                        if (route.equals("storedTool")) {
                            var result = invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, action);
                            boolean fixedFailure = result instanceof CertificateReadProofAdapter.Failure failure
                                    && "Certificate read unavailable".equals(failure.error());
                            assertThat(fixedFailure).as("tool result has the fixed failure type and message").isTrue();
                            boolean errorContainsCanary = objectMapper.writeValueAsString(result).contains(canary);
                            assertThat(errorContainsCanary)
                                    .as("authority canary absent from tool error JSON")
                                    .isFalse();
                        } else {
                            var denied = catchThrowable(
                                    () -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, action));
                            boolean deniedWithoutCause = denied instanceof AccessDeniedException
                                    && denied.getCause() == null;
                            assertThat(deniedWithoutCause)
                                    .as("authority denial has the expected type and no cause")
                                    .isTrue();
                            boolean safeDenialMessage = denied.getMessage() != null
                                    && !denied.getMessage().contains(canary);
                            assertThat(safeDenialMessage).as("authority canary absent from denial message").isTrue();
                        }
                        return true;
                    });
                    assertNoProtectedOrAssociationSql(captured.statements());
                    boolean authorityContainsCanary = AUTHORITY.exchanges
                            .getLast()
                            .response()
                            .toString()
                            .contains(canary);
                    assertThat(authorityContainsCanary).as("authority error detector positive control").isTrue();
                }
            }
            for (var event : appender.list) {
                boolean safeLogMessage = event.getFormattedMessage() != null
                        && !event.getFormattedMessage().contains(canary);
                assertThat(safeLogMessage).as("authority canary absent from named log message").isTrue();
                if (event.getThrowableProxy() != null) {
                    boolean throwableContainsCanary = ch.qos.logback.classic.spi.ThrowableProxyUtil
                            .asString(event.getThrowableProxy())
                            .contains(canary);
                    assertThat(throwableContainsCanary).as("authority canary absent from named throwable").isFalse();
                }
            }
            assertNoNamedSinkCalls(auditLogsProducer, eventProducer);
        } finally {
            levels.forEach((logger, level) -> {
                logger.detachAppender(appender);
                logger.setLevel(level);
            });
            appender.stop();
        }
    }

    @Test
    void scopedRestrictedAllowDenyIntersectionPrecedesCountAndPage() throws Exception {
        var principal = JSON
                .readTree(principal(ACTOR, profile, List.of(allowed.getUuid(), conflict.getUuid(), foreign.getUuid()),
                        List.of(conflict.getUuid()), List.of()));
        ((ObjectNode) principal.path("permissions").path("resources").get(1)).put("allowAllActions", true);
        AUTHORITY.principal = JSON.writeValueAsString(principal);
        authenticateCachedActor();
        var scope = new CertificateReadScope(profile.getUuid(),
                Set.of(allowed.getUuid(), conflict.getUuid(), foreign.getUuid()));
        var selected = new AtomicReference<List<UUID>>();
        var selectedCount = new AtomicLong();
        var filter = SecurityFilter.create();
        var captured = SqlCapture.during(() -> invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, () -> {
            var request = new CertificateSearchRequestDto();
            request.setItemsPerPage(1);
            var response = service.listCertificates(filter, request);
            selected
                    .set(certificates
                            .findUuidsUsingSecurityFilter(filter, null, PageRequest.of(0, 1),
                                    (root, cb) -> cb.desc(root.get("created"))));
            selectedCount.set(certificates.countUsingSecurityFilter(filter, null));
            return response;
        }));
        assertThat(AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/objects")
                        && e.request().at("/input/requestedResource/name").asText().equals("raProfiles")))
                .singleElement()
                .satisfies(vote -> {
                    assertThat(vote.status()).isEqualTo(200);
                    assertThat(vote.response().at("/result/actionAllowedForGroupOfObjects").asBoolean()).isTrue();
                });
        assertThat(filter.getParentResourceFilter().areOnlySpecificObjectsAllowed()).isFalse();
        assertThat(filter.getResourceFilter().getAllowedObjects()).contains(foreign.getUuid());
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(selected.get()).as("trusted-profile UUID selection").containsExactly(allowed.getUuid());
            softly.assertThat(selectedCount.get()).as("trusted-profile SQL count").isEqualTo(1);
            softly
                    .assertThat(captured.result().getCertificates())
                    .extracting(c -> UUID.fromString(c.getUuid()))
                    .containsExactly(allowed.getUuid());
            softly
                    .assertThat(captured.result().getCertificates())
                    .extracting(c -> c.getCommonName())
                    .doesNotContain(foreign.getCommonName());
            softly.assertThat(captured.result().getTotalItems()).isEqualTo(1);
            softly.assertThat(captured.result().getTotalPages()).isEqualTo(1);
        });
        assertThat(protectedSql(captured.statements())).hasSize(5).allSatisfy(sql -> {
            assertThat(sql).contains("ra_profile_uuid", "uuid");
        });
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(2);
        System.out
                .println("[AI-PROOF] scoped SQL intersection with authoritative parent-all: Auth="
                        + AUTHORITY.count("/auth") + "; method=" + AUTHORITY.count("/v1/data/method") + "; objects="
                        + AUTHORITY.count("/v1/data/objects")
                        + "; protectedSQL=5; selectedUUIDs=1; SQLcount=1; totalItems=1; totalPages=1");
        protectedSql(captured.statements())
                .forEach(sql -> System.out.println("[AI-PROOF] scoped protected SQL: " + sql));
        verifyNoInteractions(eventProducer);
    }

    @Test
    void scopedBroadGrantStillExcludesDeniedForeignAndOutOfSetRows() throws Exception {
        var principal = JSON.readTree(principal(ACTOR, profile, List.of(), List.of(conflict.getUuid()), List.of()));
        ((ObjectNode) principal.path("permissions").path("resources").get(0)).put("allowAllActions", true);
        ((ObjectNode) principal.path("permissions").path("resources").get(1)).put("allowAllActions", true);
        AUTHORITY.principal = JSON.writeValueAsString(principal);
        authenticateCachedActor();
        var scope = new CertificateReadScope(profile.getUuid(),
                Set.of(allowed.getUuid(), conflict.getUuid(), foreign.getUuid()));
        assertThat(invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, this::list)).containsExactly(allowed.getUuid());
    }

    @Test
    void scopedExplicitGrantsIgnoreOwnerAndGroupAssociationsAndDenyWins() throws Exception {
        var scope = new CertificateReadScope(profile.getUuid(),
                Set.of(allowed.getUuid(), owned.getUuid(), grouped.getUuid()));
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid(), owned.getUuid(), grouped.getUuid()),
                List.of(), List.of(group.getUuid()));
        authenticateCachedActor();
        var associated = invocation
                .call(ACTOR, scope, INVOCATION_TIMEOUT,
                        () -> service.listCertificates(SecurityFilter.create(), new CertificateSearchRequestDto()));
        assertThat(associated.getCertificates())
                .extracting(c -> UUID.fromString(c.getUuid()))
                .containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid(), grouped.getUuid());
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid(), owned.getUuid(), grouped.getUuid()),
                List.of(owned.getUuid(), grouped.getUuid()), List.of(group.getUuid()));
        assertThat(invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, this::list)).containsExactly(allowed.getUuid());
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(),
                List.of(group.getUuid()));
        assertThat(invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, this::list)).containsExactly(allowed.getUuid());
        jdbc.update("DELETE FROM core.owner_association WHERE object_uuid = ?", owned.getUuid());
        jdbc.update("DELETE FROM core.group_association WHERE object_uuid = ?", grouped.getUuid());
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid(), owned.getUuid(), grouped.getUuid()),
                List.of(), List.of(group.getUuid()));
        var unassociated = invocation
                .call(ACTOR, scope, INVOCATION_TIMEOUT,
                        () -> service.listCertificates(SecurityFilter.create(), new CertificateSearchRequestDto()));
        assertThat(unassociated.getCertificates())
                .usingRecursiveFieldByFieldElementComparatorOnFields("uuid", "commonName", "serialNumber",
                        "issuerCommonName", "fingerprint", "notBefore", "notAfter", "state", "validationStatus")
                .containsExactlyElementsOf(associated.getCertificates());
    }

    @Test
    void scopedDisjointPrincipalsAndEmptyScopeCannotReuseLegacyAssociationAccess() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(conflict.getUuid()), List.of(),
                List.of(group.getUuid()));
        authenticateCachedActor();
        assertThat(invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::list)).isEmpty();
        var otherPrincipal = JSON.readTree(principal(OTHER, profile, List.of(foreign.getUuid()), List.of(), List.of()));
        ((ObjectNode) otherPrincipal.path("permissions").path("resources").get(1)).put("allowAllActions", true);
        AUTHORITY.principal = JSON.writeValueAsString(otherPrincipal);
        assertThat(invocation
                .call(OTHER, new CertificateReadScope(profile.getUuid(), Set.of(foreign.getUuid())), INVOCATION_TIMEOUT,
                        this::list))
                .isEmpty();
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        var empty = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, new CertificateReadScope(profile.getUuid(), Set.of()), INVOCATION_TIMEOUT,
                                () -> service
                                        .listCertificates(SecurityFilter.create(), new CertificateSearchRequestDto())));
        assertThat(empty.result().getCertificates()).isEmpty();
        assertThat(empty.result().getTotalItems()).isZero();
        assertThat(empty.result().getTotalPages()).isZero();
        assertThat(protectedSql(empty.statements())).hasSize(2);
    }

    @ParameterizedTest
    @ValueSource(ints = {4, 5})
    void scopedFilterPhaseOutageAfterSuccessfulMethodVotesRunsNoSql(int failingAuth) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        list();
        AUTHORITY.exchanges.clear();
        AtomicInteger auth = new AtomicInteger();
        AUTHORITY.beforeRequest = (path, body) -> {
            if (path.equals("/auth") && auth.incrementAndGet() == failingAuth) {
                AUTHORITY.opaUnavailable = true;
            }
        };
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::list))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(failingAuth - 3L);
        assertThat(AUTHORITY.exchanges.getLast().status()).isEqualTo(503);
        System.out
                .println("[AI-PROOF] filter outage: failingAuth=" + failingAuth + "; method=2; objects="
                        + AUTHORITY.count("/v1/data/objects") + "; protectedSQL=0; associationSQL=0");
        verifyNoInteractions(eventProducer);
    }

    @Test
    void scopedRepositoryRejectsAbsentOrUncompletedFilterBeforeBusinessQuery() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var captured = SqlCapture.during(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
            assertThatThrownBy(() -> certificates.findUuidsUsingSecurityFilter(null, null, null, null))
                    .isInstanceOf(AccessDeniedException.class);
            var uncompleted = SecurityFilter.create();
            assertThatThrownBy(() -> certificates.countUsingSecurityFilter(uncompleted, null))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        }));
        assertNoProtectedOrAssociationSql(captured.statements());
    }

    @Test
    void scopedSecondProjectionRejectsRowMovedAfterUuidSelection() throws Exception {
        var principal = JSON.readTree(principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        ((ObjectNode) principal.path("permissions").path("resources").get(1)).put("allowAllActions", true);
        AUTHORITY.principal = JSON.writeValueAsString(principal);
        authenticateCachedActor();
        assertThat(invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::list))
                .containsExactly(allowed.getUuid());
        var barrier = new CyclicBarrier(2);
        var projected = new AtomicBoolean();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var moved = executor.submit(() -> {
                barrier.await(5, TimeUnit.SECONDS);
                jdbc
                        .update("UPDATE core.certificate SET ra_profile_uuid = ?, common_name = ? WHERE uuid = ?",
                                foreignProfile.getUuid(), "foreign-projection-canary", allowed.getUuid());
                barrier.await(5, TimeUnit.SECONDS);
                return true;
            });
            var captured = SqlCapture
                    .during(() -> invocation
                            .call(ACTOR, readScope, Duration.ofSeconds(10), () -> service
                                    .listCertificates(SecurityFilter.create(), new CertificateSearchRequestDto())),
                            sql -> {
                                if (sql.contains("from core.certificate ") && sql.contains("issuer_common_name")
                                        && projected.compareAndSet(false, true)) {
                                    try {
                                        barrier.await(5, TimeUnit.SECONDS);
                                        barrier.await(5, TimeUnit.SECONDS);
                                    } catch (Exception failure) {
                                        throw new IllegalStateException(failure);
                                    }
                                }
                            });
            assertThat(moved.get(5, TimeUnit.SECONDS)).isTrue();
            assertThat(projected).isTrue();
            assertThat(AUTHORITY.exchanges
                    .stream()
                    .filter(e -> e.path().equals("/v1/data/objects")
                            && e.request().at("/input/requestedResource/name").asText().equals("raProfiles")))
                    .hasSize(2)
                    .allSatisfy(vote -> {
                        assertThat(vote.status()).isEqualTo(200);
                        assertThat(vote.response().at("/result/actionAllowedForGroupOfObjects").asBoolean()).isTrue();
                    });
            SoftAssertions.assertSoftly(softly -> {
                softly
                        .assertThat(captured.result().getCertificates())
                        .as("trusted-profile second projection")
                        .isEmpty();
                softly
                        .assertThat(captured.result().getCertificates())
                        .extracting(c -> c.getCommonName())
                        .doesNotContain("foreign-projection-canary");
                softly.assertThat(captured.result().getTotalItems()).isZero();
            });
            assertThat(protectedSql(captured.statements())).hasSize(3);
            System.out
                    .println(
                            "[AI-PROOF] projection migration barrier with authoritative parent-all: selected row moved to foreign profile; projected=0; totalItems=0; protectedSQL=3");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "parent",
            "path",
            "foreignPath",
            "resource",
            "resourceFilter",
            "action",
            "parentResource",
            "parentAction",
            "entity"})
    void scopedRepositoryRejectsIncompleteOrUnexpectedMetadata(String missing) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
            var filter = SecurityFilter.create();
            service.listCertificates(filter, new CertificateSearchRequestDto());
            switch (missing) {
                case "parent" -> filter.setParentResourceFilter(null);
                case "path" -> filter.setParentRefProperty(null);
                case "foreignPath" -> filter.setParentRefProperty("raProfile.name");
                case "resourceFilter" -> filter.setResourceFilter(null);
                case "parentResource" -> filter.getParentResourceFilter().setResource(Resource.CERTIFICATE);
                case "parentAction" -> filter.getParentResourceFilter().setResourceAction(ResourceAction.LIST);
                case "entity" -> assertThat(filter.getCompletedInvocationUuid()).isNotNull();
                case "resource" -> filter.getResourceFilter().setResource(Resource.RA_PROFILE);
                case "action" -> filter.getResourceFilter().setResourceAction(ResourceAction.DETAIL);
                default -> throw new IllegalArgumentException();
            }
            SecurityFilterRepository<?, UUID> repository = missing.equals("entity") ? profiles : certificates;
            var captured = SqlCapture.during(() -> {
                assertThatThrownBy(() -> repository.countUsingSecurityFilter(filter, null))
                        .isInstanceOf(AccessDeniedException.class);
                return true;
            });
            assertNoProtectedOrAssociationSql(captured.statements());
            return true;
        });
    }

    @Test
    void scopedRepositoryRejectsFilterReusedAcrossInvocationAndPrincipal() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var filter = SecurityFilter.create();
        invocation
                .call(ACTOR, readScope, INVOCATION_TIMEOUT,
                        () -> service.listCertificates(filter, new CertificateSearchRequestDto()));
        for (UUID actor : List.of(ACTOR, OTHER)) {
            AUTHORITY.principal = principal(actor, profile, List.of(allowed.getUuid()), List.of(), List.of());
            var captured = SqlCapture.during(() -> invocation.call(actor, readScope, INVOCATION_TIMEOUT, () -> {
                assertThatThrownBy(() -> certificates.countUsingSecurityFilter(filter, null))
                        .isInstanceOf(AccessDeniedException.class);
                return true;
            }));
            assertNoProtectedOrAssociationSql(captured.statements());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {101, 1000})
    void scopedOversizedPageStopsBeforeSql(int size) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                var request = new CertificateSearchRequestDto();
                request.setItemsPerPage(size);
                return service.listCertificates(SecurityFilter.create(), request);
            })).isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
    }

    @Test
    void scopedEleventhPageStopsBeforeSql() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                var request = new CertificateSearchRequestDto();
                request.setPageNumber(11);
                return service.listCertificates(SecurityFilter.create(), request);
            })).isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
    }

    @Test
    void scopedSubsecondBudgetCannotStartProtectedSql() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var budget = Duration.ofMillis(900);
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, budget, this::list))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(2);
    }

    @Test
    void scopedMergedRoleGrantsStillIntersectAllExplicitDenies() throws Exception {
        var principal = JSON
                .readTree(principal(ACTOR, profile, List.of(allowed.getUuid(), conflict.getUuid()), List.of(),
                        List.of()));
        var secondRole = JSON
                .readTree(principal(ACTOR, profile, List.of(owned.getUuid(), conflict.getUuid()),
                        List.of(conflict.getUuid()), List.of()));
        ((ArrayNode) principal.path("roles")).addObject().put("name", "synthetic-role-a");
        ((ArrayNode) principal.path("roles")).addObject().put("name", "synthetic-role-b");
        ((ArrayNode) principal.path("permissions").path("resources"))
                .add(secondRole.path("permissions").path("resources").get(0));
        AUTHORITY.principal = JSON.writeValueAsString(principal);
        authenticateCachedActor();
        var scope = new CertificateReadScope(profile.getUuid(),
                Set.of(allowed.getUuid(), conflict.getUuid(), owned.getUuid()));
        assertThat(invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, this::list))
                .containsExactlyInAnyOrder(allowed.getUuid(), owned.getUuid());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void scopedParentDenyWinsAfterSuccessfulOuterMethodVotes(boolean broad) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        String initial = AUTHORITY.principal;
        AtomicInteger auth = new AtomicInteger();
        AUTHORITY.beforeRequest = (path, body) -> {
            if (path.equals("/auth") && auth.incrementAndGet() == 4) {
                try {
                    var updated = JSON.readTree(initial);
                    var parent = (ObjectNode) updated.path("permissions").path("resources").get(1);
                    parent.put("allowAllActions", broad);
                    ((ObjectNode) parent.path("objects").get(0)).putArray("deny").add("members");
                    AUTHORITY.principal = JSON.writeValueAsString(updated);
                } catch (Exception failure) {
                    throw new IllegalStateException(failure);
                }
            }
        };
        var response = invocation
                .call(ACTOR, readScope, INVOCATION_TIMEOUT,
                        () -> service.listCertificates(SecurityFilter.create(), new CertificateSearchRequestDto()));
        assertThat(response.getCertificates()).isEmpty();
        assertThat(response.getTotalItems()).isZero();
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/objects")).isEqualTo(2);
    }

    @Test
    void scopedSlowPostgresQueryIsCancelledByBoundedJdbcTimeout() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var elapsed = new AtomicLong();
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, Duration.ofSeconds(3), () -> {
                var filter = SecurityFilter.create();
                service.listCertificates(filter, new CertificateSearchRequestDto());
                long started = System.nanoTime();
                try {
                    return certificates
                            .countUsingSecurityFilter(filter, (root, cb, query) -> cb
                                    .isNotNull(cb.function("pg_sleep", String.class, cb.literal(4))));
                } finally {
                    elapsed.set(System.nanoTime() - started);
                }
            }))
                    .hasRootCauseInstanceOf(PSQLException.class)
                    .rootCause()
                    .extracting(failure -> ((PSQLException) failure).getSQLState())
                    .isEqualTo("57014");
            return true;
        });
        assertThat(Duration.ofNanos(elapsed.get())).isBetween(Duration.ofMillis(900), Duration.ofMillis(3500));
        assertThat(protectedSql(captured.statements())).hasSize(4);
        assertThat(protectedSql(captured.statements()).getLast()).contains("pg_sleep");
        verifyNoInteractions(eventProducer);
        System.out
                .println("[AI-PROOF] bounded PostgreSQL query cancelled: SQLSTATE=57014; milliseconds="
                        + Duration.ofNanos(elapsed.get()).toMillis());
    }

    @Test
    void scopedSecondProjectionCannotTreatCompletionStampAsAnObjectGrant() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid(), conflict.getUuid()),
                List.of(conflict.getUuid()), List.of());
        authenticateCachedActor();
        var scope = new CertificateReadScope(profile.getUuid(), Set.of(allowed.getUuid(), conflict.getUuid()));
        invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, () -> {
            var filter = SecurityFilter.create();
            service.listCertificates(filter, new CertificateSearchRequestDto());
            assertThat(certificates.findScopedCertificateDtos(filter, List.of(conflict.getUuid()))).isEmpty();
            filter.getParentResourceFilter().getForbiddenObjects().add(profile.getUuid());
            assertThat(certificates.findScopedCertificateDtos(filter, List.of(allowed.getUuid()))).isEmpty();
            return true;
        });
    }

    @Test
    void scopedSecondProjectionRejectsOutOfScopeOrOversizedPageBeforeSql() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
            var filter = SecurityFilter.create();
            service.listCertificates(filter, new CertificateSearchRequestDto());
            var captured = SqlCapture.during(() -> {
                var outsideScope = List.of(foreign.getUuid());
                assertThatThrownBy(() -> certificates.findScopedCertificateDtos(filter, outsideScope))
                        .isInstanceOf(AccessDeniedException.class);
                var oversized = Collections.nCopies(101, allowed.getUuid());
                assertThatThrownBy(() -> certificates.findScopedCertificateDtos(filter, oversized))
                        .isInstanceOf(AccessDeniedException.class);
                return true;
            });
            assertNoProtectedOrAssociationSql(captured.statements());
            return true;
        });
    }

    @Test
    void storedHealthUsesTwoActualVotesThenOneBoundedTupleSelect() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, readScope, INVOCATION_TIMEOUT,
                                () -> service
                                        .getStoredCertificateHealth(SecuredParentUUID.fromUUID(profile.getUuid()),
                                                SecuredUUID.fromUUID(allowed.getUuid()))));
        assertThat(captured.result()).isNotNull();
        assertThat(captured.result().certificateUuid()).isEqualTo(allowed.getUuid());
        assertThat(captured.result().evidence()).isEqualTo(StoredCertificateHealth.Evidence.MISSING);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        assertThat(AUTHORITY.count("/v1/data/objects")).isZero();
        assertThat(protectedSql(captured.statements())).hasSize(1);
        assertThat(protectedSql(captured.statements()).getFirst()).contains("substr", "100001", "ra_profile_uuid");
        String tupleSql = protectedSql(captured.statements()).getFirst();
        String where = tupleSql.substring(tupleSql.indexOf(" where ") + 7);
        assertThat(where).containsPattern("\\.uuid=\\?").containsPattern("\\.uuid in \\(");
        long profilePredicates = java.util.regex.Pattern
                .compile("\\.ra_profile_uuid=\\?")
                .matcher(where)
                .results()
                .count();
        assertThat(profilePredicates).isEqualTo(2);

        assertNoNamedSinkCalls(eventProducer);
    }

    @Test
    void proofAdapterDispatchesSearchToActualScopedService() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var adapter = new CertificateReadProofAdapter(service,
                Clock.fixed(Instant.parse("2026-10-27T00:00:00Z"), ZoneOffset.UTC));
        var captured = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> adapter
                                .dispatch(
                                        "{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":10}}")));
        assertThat(captured.result()).isNotInstanceOf(CertificateReadProofAdapter.Failure.class);
        assertThat(protectedSql(captured.statements())).hasSize(3);
        assertNoNamedSinkCalls(eventProducer);
    }

    @ParameterizedTest
    @ValueSource(strings = {"complete", "missing", "stale", "malformed", "future"})
    void storedHealthPreservesActualStoredEvidenceWithoutValidation(String fixture) throws Exception {
        var time = java.time.OffsetDateTime.parse("2026-10-27T00:00:00Z");
        if (fixture.equals("stale")) {
            time = time.minusDays(2);
        }
        if (fixture.equals("future")) {
            time = time.plusDays(2);
        }
        String raw = switch (fixture) {
            case "missing" -> null;
            case "malformed" -> "{broken-STORED_MESSAGE_CANARY";
            default -> "{\"signature\":{\"status\":\"valid\",\"message\":\"STORED_MESSAGE_CANARY\"}}";
        };
        jdbc
                .update("UPDATE core.certificate SET certificate_validation_result=?, status_validation_timestamp=? WHERE uuid=?",
                        raw, time, allowed.getUuid());
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var before = completeBusinessSnapshot();
        var captured = SqlCapture
                .during(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::storedAllowed));
        var expected = switch (fixture) {
            case "missing" -> StoredCertificateHealth.Evidence.MISSING;
            case "malformed" -> StoredCertificateHealth.Evidence.MALFORMED;
            default -> StoredCertificateHealth.Evidence.PRESENT;
        };
        assertThat(captured.result().evidence()).isEqualTo(expected);
        assertThat(captured.result().validationTimestamp().toInstant()).isEqualTo(time.toInstant());
        assertThat(captured.result().validationStatus()).isEqualTo(CertificateValidationStatus.VALID);
        boolean containsStoredMessage = objectMapper
                .writeValueAsString(captured.result())
                .contains("STORED_MESSAGE_CANARY");
        assertThat(containsStoredMessage).as("stored message excluded").isFalse();
        assertThat(protectedSql(captured.statements())).hasSize(1);
        assertThat(captured.statements()).noneMatch(AiCertificateReadProofITest::isBusinessDml);
        boolean rowsUnchanged = completeBusinessSnapshot().equals(before);
        assertThat(rowsUnchanged).as("complete business rows unchanged").isTrue();
        assertNoNamedSinkCalls(eventProducer);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "nullParent",
            "nullParentUuid",
            "wrongProfile",
            "nullCertificate",
            "nullCertificateUuid",
            "parentAsCertificate",
            "outOfSet"})
    void storedHealthRejectsInvalidSuppliedArgumentsBeforeVotesAndProtectedSql(String shape) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid(), conflict.getUuid()), List.of(),
                List.of());
        authenticateCachedActor();
        SecuredParentUUID parent = shape.equals("nullParent")
                ? null
                : SecuredParentUUID
                        .fromUUID(shape.equals("nullParentUuid")
                                ? null
                                : shape.equals("wrongProfile") ? foreignProfile.getUuid() : profile.getUuid());
        SecuredUUID certificate = switch (shape) {
            case "nullCertificate" -> null;
            case "nullCertificateUuid" -> SecuredUUID.fromUUID(null);
            case "parentAsCertificate" -> SecuredParentUUID.fromUUID(allowed.getUuid());
            case "outOfSet" -> SecuredUUID.fromUUID(conflict.getUuid());
            default -> SecuredUUID.fromUUID(allowed.getUuid());
        };
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation
                    .call(ACTOR, readScope, INVOCATION_TIMEOUT,
                            () -> service.getStoredCertificateHealth(parent, certificate)))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/v1/data/method")).isZero();
        if (!shape.equals("wrongProfile") && !shape.equals("outOfSet")) {
            AUTHORITY.exchanges.clear();
            var ordinary = SqlCapture.during(() -> {
                assertThatThrownBy(() -> service.getStoredCertificateHealth(parent, certificate))
                        .isInstanceOf(AccessDeniedException.class);
                return true;
            });
            assertNoProtectedOrAssociationSql(ordinary.statements());
            assertThat(AUTHORITY.count("/v1/data/method")).isZero();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"parentDeny", "resourceDeny", "parentOutage", "resourceOutage"})
    void storedHealthDenialAndOutagePrecedeTupleSql(String failure) throws Exception {
        var grantedProfile = failure.equals("parentDeny") ? foreignProfile : profile;
        AUTHORITY.principal = principal(ACTOR, grantedProfile,
                failure.equals("resourceDeny") ? List.of() : List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        AUTHORITY.exchanges.clear();
        AUTHORITY.beforeRequest = (path, body) -> {
            String name = body.at("/input/requestedResource/name").asText();
            if (path.equals("/v1/data/method") && ((failure.equals("parentOutage") && name.equals("raProfiles"))
                    || (failure.equals("resourceOutage") && name.equals("certificates")))) {
                AUTHORITY.opaUnavailable = true;
            }
        };
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::storedAllowed))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(failure.startsWith("parent") ? 1 : 2);
        if (failure.endsWith("Outage")) {
            assertThat(AUTHORITY.exchanges.getLast().status()).isEqualTo(503);
        } else {
            assertThat(AUTHORITY.exchanges.getLast().response().at("/result/authorized").asBoolean()).isFalse();
        }
        assertNoNamedSinkCalls(eventProducer);
    }

    @Test
    void storedHealthTrustedUuidUnderAnotherProfileReturnsNoContentAfterOneTupleQuery() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(foreign.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var scope = new CertificateReadScope(profile.getUuid(), Set.of(foreign.getUuid()));
        var published = new AtomicReference<StoredCertificateHealth>();
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, () -> {
                var result = service
                        .getStoredCertificateHealth(SecuredParentUUID.fromUUID(profile.getUuid()),
                                SecuredUUID.fromUUID(foreign.getUuid()));
                published.set(result);
                return result;
            }))
                    .isInstanceOf(com.otilm.api.exception.NotFoundException.class)
                    .hasMessage("Stored certificate health unavailable");
            return true;
        });
        assertThat(published.get()).isNull();
        assertThat(protectedSql(captured.statements())).hasSize(1);
        assertNoNamedSinkCalls(eventProducer);
    }

    @Test
    void storedHealthIsIndependentlyAuthorizedOutsideAiScope() throws Exception {
        authenticate(ACTOR, principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of()));
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture.during(this::storedAllowed);
        assertThat(captured.result().certificateUuid()).isEqualTo(allowed.getUuid());
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        assertThat(protectedSql(captured.statements())).hasSize(1);
        assertThat(AiReadInvocationContext.isActive()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"parentDeny", "resourceDeny", "tupleMismatch"})
    void storedHealthOrdinaryDenialUsesActualRequestedObjectsAndTuple(String scenario) throws Exception {
        var target = scenario.equals("tupleMismatch") ? foreign : allowed;
        var grantedProfile = scenario.equals("parentDeny") ? foreignProfile : profile;
        var grantedCertificates = scenario.equals("resourceDeny") ? List.<UUID>of() : List.of(target.getUuid());
        authenticate(ACTOR, principal(ACTOR, grantedProfile, grantedCertificates, List.of(), List.of()));
        AUTHORITY.exchanges.clear();
        var published = new AtomicReference<StoredCertificateHealth>();
        var captured = SqlCapture.during(() -> {
            var failure = assertThatThrownBy(() -> {
                var result = service
                        .getStoredCertificateHealth(SecuredParentUUID.fromUUID(profile.getUuid()),
                                SecuredUUID.fromUUID(target.getUuid()));
                published.set(result);
            });
            if (scenario.equals("tupleMismatch")) {
                failure
                        .isInstanceOf(com.otilm.api.exception.NotFoundException.class)
                        .hasMessage("Stored certificate health unavailable");
            } else {
                failure.isInstanceOf(AccessDeniedException.class);
            }
            return true;
        });
        assertThat(published.get()).isNull();
        var votes = AUTHORITY.exchanges.stream().filter(e -> e.path().equals("/v1/data/method")).toList();
        int voteCount = votes.size();
        assertThat(voteCount).isEqualTo(scenario.equals("parentDeny") ? 1 : 2);
        assertThat(votes.getFirst().request().at("/input/requestedResource/name").asText()).isEqualTo("raProfiles");
        assertThat(votes.getFirst().request().at("/input/requestedResource/uuids/0").asText())
                .isEqualTo(profile.getUuid().toString());
        if (!scenario.equals("parentDeny")) {
            assertThat(votes.getLast().request().at("/input/requestedResource/name").asText())
                    .isEqualTo("certificates");
            assertThat(votes.getLast().request().at("/input/requestedResource/uuids/0").asText())
                    .isEqualTo(target.getUuid().toString());
        }
        assertThat(protectedSql(captured.statements())).hasSize(scenario.equals("tupleMismatch") ? 1 : 0);
        assertThat(AiReadInvocationContext.isActive()).isFalse();
        assertNoNamedSinkCalls(eventProducer);
    }

    @ParameterizedTest
    @ValueSource(strings = {"wrongProfile", "outOfSet"})
    void storedHealthRepositoryIndependentlyRejectsTuplesBeforeSql(String scenario) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid(), conflict.getUuid()), List.of(),
                List.of());
        authenticateCachedActor();
        var suppliedProfile = scenario.equals("wrongProfile") ? foreignProfile.getUuid() : profile.getUuid();
        var suppliedCertificate = scenario.equals("outOfSet") ? conflict.getUuid() : allowed.getUuid();
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation
                    .call(ACTOR, readScope, INVOCATION_TIMEOUT,
                            () -> certificates.findStoredCertificateHealth(suppliedProfile, suppliedCertificate)))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertThat(protectedSql(captured.statements())).isEmpty();
        assertThat(AUTHORITY.count("/v1/data/method")).isZero();
    }

    @Test
    void storedHealthSubsecondBudgetAfterTwoSuccessfulVotesCannotStartSql() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        AUTHORITY.exchanges.clear();
        var timeout = Duration.ofMillis(950);
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, timeout, this::storedAllowed))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
        boolean successfulMethodVotes = AUTHORITY.exchanges
                .stream()
                .filter(e -> e.path().equals("/v1/data/method"))
                .allMatch(e -> e.response().at("/result/authorized").asBoolean());
        assertThat(successfulMethodVotes).as("both method votes were successful").isTrue();
        assertThat(AiReadInvocationContext.isActive()).isFalse();
    }

    @Test
    void storedHealthSlowTupleQueryIsCancelledByBoundedJdbcTimeout() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var started = new AtomicLong();
        try (var lock = java.util.Objects.requireNonNull(jdbc.getDataSource()).getConnection()) {
            lock.setAutoCommit(false);
            try (var statement = lock.createStatement()) {
                statement.execute("LOCK TABLE core.certificate IN ACCESS EXCLUSIVE MODE");
            }
            try {
                var captured = SqlCapture.during(() -> {
                    assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                        started.set(System.nanoTime());
                        return storedAllowed();
                    }))
                            .hasRootCauseInstanceOf(PSQLException.class)
                            .rootCause()
                            .extracting(value -> ((PSQLException) value).getSQLState())
                            .isEqualTo("57014");
                    return true;
                });
                assertThat(protectedSql(captured.statements())).hasSize(1);
                assertThat(Duration.ofNanos(System.nanoTime() - started.get()))
                        .isBetween(Duration.ofMillis(900), Duration.ofMillis(3500));
            } finally {
                lock.rollback();
            }
        }
        assertThat(AiReadInvocationContext.isActive()).isFalse();
        assertNoNamedSinkCalls(eventProducer);
    }

    @Test
    void proofAdapterRejectsEveryUntrustedArgumentFamilyBeforeDispatch() throws Exception {
        var adapter = proofAdapter();
        List<String> rejected = List
                .of("{}", "null", "[]", "{} {}", "{\"tool\":\"certificate.delete\",\"arguments\":{}}",
                        "{\"tool\":\"certificate.search\",\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":1}}",
                        "{\"tool\":\"certificate.storedHealth\",\"arguments\":{\"certificateUuid\":\"not-a-uuid\"}}");
        var inputs = new java.util.ArrayList<>(rejected);
        for (String arguments : List
                .of("{}", "{\"page\":1}", "{\"page\":\"1\",\"pageSize\":1}", "{\"page\":1.0,\"pageSize\":1}",
                        "{\"page\":0,\"pageSize\":1}", "{\"page\":11,\"pageSize\":1}", "{\"page\":1,\"pageSize\":101}",
                        "{\"page\":1,\"pageSize\":1,\"states\":[]}",
                        "{\"page\":1,\"pageSize\":1,\"states\":[\"unknown\"]}",
                        "{\"page\":1,\"pageSize\":1,\"validationStatuses\":null}",
                        "{\"page\":1,\"pageSize\":1,\"expiresBefore\":{}}")) {
            inputs.add("{\"tool\":\"certificate.search\",\"arguments\":" + arguments + "}");
        }
        for (String field : List
                .of("filters", "columns", "sort", "attributes", "actor", "profile", "raProfileUuid", "regex",
                        "wildcard", "operator", "includeArchived")) {
            inputs
                    .add("{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":1,\"" + field
                            + "\":\"ARGUMENT_CANARY\"}}");
            inputs
                    .add("{\"tool\":\"certificate.storedHealth\",\"arguments\":{\"certificateUuid\":\""
                            + allowed.getUuid() + "\",\"" + field + "\":{}}}");
        }
        inputs.add(null);
        inputs
                .add("{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":1},\"actor\":\"override\"}");
        for (String tool : List
                .of("certificate.revoke", "certificate.renew", "certificate.issue", "certificate.register",
                        "certificate.download", "certificate.validation", "certificate.chain", "unknown")) {
            inputs.add("{\"tool\":\"" + tool + "\",\"arguments\":{}}");
        }
        inputs.add("{\"tool\":\"certificate.search\",\"arguments\":{\"page\":" + "9".repeat(65) + ",\"pageSize\":1}}");
        inputs.add(" ".repeat(1048577));
        inputs
                .add("{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":1,\"states\":[\""
                        + "a".repeat(65537) + "\"]}}");
        inputs.add("[".repeat(33) + "0" + "]".repeat(33));
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture.during(() -> {
            for (var input : inputs) {
                assertThat(adapter.dispatch(input))
                        .isEqualTo(new CertificateReadProofAdapter.Failure("Invalid certificate read arguments"));
            }
            return true;
        });
        assertThat(AUTHORITY.exchanges).isEmpty();
        assertNoProtectedOrAssociationSql(captured.statements());
        assertNoNamedSinkCalls(eventProducer);
    }

    @Test
    void storedHealthTextOverflowIsBoundedInSqlAndNeverPublished() throws Exception {
        String originalType = jdbc
                .queryForObject(
                        "SELECT format_type(atttypid,atttypmod) FROM pg_attribute WHERE attrelid='core.certificate'::regclass AND attname='certificate_validation_result'",
                        String.class);
        assertThat(originalType).isEqualTo("character varying(100000)");
        jdbc.execute("ALTER TABLE core.certificate ALTER COLUMN certificate_validation_result TYPE TEXT");
        try {
            String oversized = "{\"signature\":{\"status\":\"valid\",\"message\":\"" + "x".repeat(100001) + "\"}}";
            jdbc
                    .update("UPDATE core.certificate SET certificate_validation_result=? WHERE uuid=?", oversized,
                            allowed.getUuid());
            AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
            authenticateCachedActor();
            var captured = SqlCapture
                    .during(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::storedAllowed));
            assertThat(captured.result().evidence()).isEqualTo(StoredCertificateHealth.Evidence.MALFORMED);
            assertThat(captured.result().checks()).isEmpty();
            assertThat(protectedSql(captured.statements()))
                    .singleElement()
                    .satisfies(sql -> assertThat(sql).contains("substr", "100001").doesNotContain("length("));
            for (int characters : List.of(100000, 100001)) {
                String prefix = "{\"signature\":{\"status\":\"valid\",\"message\":\"";
                String suffix = "\"}}";
                String unicode = prefix + "😀".repeat(characters - prefix.length() - suffix.length()) + suffix;
                assertThat(unicode.codePointCount(0, unicode.length())).isEqualTo(characters);
                assertThat(unicode.length()).isGreaterThan(100000);
                jdbc
                        .update("UPDATE core.certificate SET certificate_validation_result=? WHERE uuid=?", unicode,
                                allowed.getUuid());
                var unicodeRead = SqlCapture
                        .during(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, this::storedAllowed));
                assertThat(protectedSql(unicodeRead.statements()))
                        .singleElement()
                        .satisfies(sql -> assertThat(sql).contains("substr", "100001").doesNotContain("length("));
                assertThat(unicodeRead.result().evidence())
                        .isEqualTo(characters == 100000
                                ? StoredCertificateHealth.Evidence.PRESENT
                                : StoredCertificateHealth.Evidence.MALFORMED);
                if (characters == 100000) {
                    assertThat(unicodeRead.result().checks())
                            .containsEntry(
                                    com.otilm.api.model.core.certificate.CertificateValidationCheck.SIGNATURE_VERIFICATION,
                                    CertificateValidationStatus.VALID);
                } else {
                    assertThat(unicodeRead.result().checks()).isEmpty();
                }
            }
        } finally {
            jdbc
                    .update("UPDATE core.certificate SET certificate_validation_result=NULL WHERE uuid=?",
                            allowed.getUuid());
            jdbc
                    .execute(
                            "ALTER TABLE core.certificate ALTER COLUMN certificate_validation_result TYPE VARCHAR(100000)");
            assertThat(jdbc
                    .queryForObject(
                            "SELECT format_type(atttypid,atttypmod) FROM pg_attribute WHERE attrelid='core.certificate'::regclass AND attname='certificate_validation_result'",
                            String.class))
                    .isEqualTo(originalType);
        }
    }

    @Test
    void wholeScriptedReportHasOnlySafeFieldsAndLeavesEveryBusinessRowAndNamedSinkUnchangedAfterOsivCommit()
            throws Exception {
        var future = certificate(profile, "future.synthetic");
        List<Certificate> scripted = List.of(allowed, conflict, owned, grouped, future);
        List<String> canaries = List
                .of("CREDENTIAL_CANARY", "KEY_MATERIAL_CANARY", "REGISTRATION_SECRET_CANARY",
                        "LIFECYCLE_ATTRIBUTE_CANARY", "CUSTOM_ATTRIBUTE_CANARY", "COMPLIANCE_CANARY",
                        "STORED_MESSAGE_CANARY", "HISTORY_CANARY", "REQUEST_CANARY");
        seedReportSecrets(canaries);
        var now = java.time.OffsetDateTime.parse("2026-10-27T00:00:00Z");
        for (int index = 0; index < scripted.size(); index++) {
            String raw = index == 1
                    ? null
                    : index == 3
                            ? "{malformed"
                            : "{\"signature\":{\"status\":\"valid\",\"message\":\"" + canaries.get(6) + "\"}}";
            var time = index == 2 ? now.minusDays(2) : index == 4 ? now.plusSeconds(1) : now;
            jdbc
                    .update("UPDATE core.certificate SET certificate_validation_result=?, status_validation_timestamp=? WHERE uuid=?",
                            raw, time, scripted.get(index).getUuid());
        }
        var uuids = scripted.stream().map(Certificate::getUuid).collect(java.util.stream.Collectors.toSet());
        var scope = new CertificateReadScope(profile.getUuid(), uuids);
        AUTHORITY.principal = principal(ACTOR, profile, List.copyOf(uuids), List.of(), List.of());
        authenticateCachedActor();
        var before = completeBusinessSnapshot();
        for (String canary : canaries) {
            assertThat(before.values().stream().flatMap(List::stream).anyMatch(row -> row.contains(canary)))
                    .as("named fixture canary is present")
                    .isTrue();
        }
        var adapter = proofAdapter();
        clearInvocations(eventProducer, validationProducer, notificationProducer, actionProducer, connectorCalls,
                auditLogsProducer);
        recordedMessages.clear();
        proofEvents.publishEvent(new com.otilm.core.events.transaction.CertificateValidationEvent(List.of()));
        proofEvents
                .publishEvent(new com.otilm.core.events.transaction.UpdateCertificateHistoryEvent(allowed.getUuid(),
                        null, null, "Synthetic detector control", null));
        assertThat(recordedMessages.certificateEvents()).containsExactly("validation", "history");
        recordedMessages.clear();
        var appender = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        appender.start();
        List<String> loggerNames = List
                .of("com.otilm.core.security.authn.client.PlatformAuthenticationClient",
                        "com.otilm.core.security.authn.client.PlatformBaseAuthenticationClient",
                        "com.otilm.core.security.authz.opa.OpaClient",
                        "com.otilm.core.security.authz.ExternalAuthorizationCore",
                        "com.otilm.core.service.impl.CertificateServiceImpl",
                        "com.otilm.core.service.handler.StoredCertificateHealthProjector",
                        "com.otilm.core.util.ai.CertificateReadProofAdapter",
                        "com.otilm.core.service.impl.AuditLogServiceImpl",
                        "com.otilm.core.messaging.jms.producers.AuditLogsProducer");
        var levels = new java.util.HashMap<ch.qos.logback.classic.Logger, ch.qos.logback.classic.Level>();
        for (String name : loggerNames) {
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(name);
            levels.put(logger, logger.getLevel());
            logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
            logger.addAppender(appender);
        }
        EntityManager em = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(em));
        try {
            var observed = SqlCapture.during(() -> {
                var safeJson = invocation.call(ACTOR, scope, Duration.ofSeconds(10), () -> {
                    Object search = adapter
                            .dispatch("{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":2}}");
                    assertThat(search).isInstanceOf(CertificateReadProofAdapter.SearchResult.class);
                    Object detail = adapter
                            .dispatch("{\"tool\":\"certificate.storedHealth\",\"arguments\":{\"certificateUuid\":\""
                                    + allowed.getUuid() + "\"}}");
                    assertThat(detail).isInstanceOf(StoredCertificateHealth.class);
                    var report = adapter
                            .report(new CertificateReadProofAdapter.SearchArguments(1, 2, null, null, null));
                    assertThat(report.allPagesRead()).isTrue();
                    assertThat(report.stoppedAtLimit()).isFalse();
                    assertObservationsContract(report);
                    assertThat(report.pagesRead()).isEqualTo(3);
                    assertThat(report.observedTotal()).isEqualTo(5);
                    assertThat(report.trustedCertificateCount()).isEqualTo(5);
                    assertThat(report.raProfileUuid()).isEqualTo(profile.getUuid());
                    assertThat(report.certificates()).hasSize(5);
                    assertThat(report.certificates().stream().map(CertificateReadProofAdapter.ReportEntry::freshness))
                            .containsExactlyInAnyOrder(CertificateReadProofAdapter.Freshness.CURRENT,
                                    CertificateReadProofAdapter.Freshness.MISSING,
                                    CertificateReadProofAdapter.Freshness.STALE,
                                    CertificateReadProofAdapter.Freshness.MISSING,
                                    CertificateReadProofAdapter.Freshness.INCONSISTENT);
                    assertThat(report.certificates().stream().map(e -> e.stored().evidence()))
                            .contains(StoredCertificateHealth.Evidence.MALFORMED);
                    return List
                            .of(objectMapper.writeValueAsString(search), objectMapper.writeValueAsString(detail),
                                    objectMapper.writeValueAsString(report),
                                    "{\"evidenceBasis\":\"OBSERVATIONS\",\"rows\":5,\"namedSinksObserved\":true}");
                });
                assertThat(em.unwrap(Session.class).isDirty()).isFalse();
                new TransactionTemplate(transactions).executeWithoutResult(status -> em.flush());
                em.clear();
                return safeJson;
            });
            assertThat(protectedSql(observed.statements())).hasSize(18);
            assertThat(observed.statements()).noneMatch(AiCertificateReadProofITest::isBusinessDml);
            boolean rowsUnchanged = completeBusinessSnapshot().equals(before);
            assertThat(rowsUnchanged).as("all full business rows unchanged after later committed OSIV flush").isTrue();
            for (String sink : observed.result()) {
                for (String canary : canaries) {
                    boolean containsCanary = sink.contains(canary);
                    assertThat(containsCanary).as("named tool/report/evidence canary excluded").isFalse();
                }
                boolean containsExcludedCertificate = sink.contains(foreign.getUuid().toString());
                assertThat(containsExcludedCertificate).as("excluded certificate absent from safe sinks").isFalse();
            }
            assertThat(observed
                    .result()
                    .stream()
                    .allMatch(text -> !text.contains("attributeValues") && !text.contains("owner")
                            && !text.contains("groups")))
                    .as("excluded DTO fields absent")
                    .isTrue();
            for (var event : appender.list) {
                String log = event.getFormattedMessage() + (event.getThrowableProxy() == null
                        ? ""
                        : ch.qos.logback.classic.spi.ThrowableProxyUtil.asString(event.getThrowableProxy()));
                for (String canary : canaries) {
                    boolean containsCanary = log.contains(canary);
                    assertThat(containsCanary).as("named test-log canary excluded").isFalse();
                }
            }
            int notificationCount = recordedMessages.messages().size();
            assertThat(notificationCount).as("no notification event was published").isZero();
            assertThat(recordedMessages.certificateEvents()).isEmpty();
            assertNoNamedSinkCalls(eventProducer, validationProducer, notificationProducer, actionProducer,
                    connectorCalls, auditLogsProducer);
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            em.close();
            levels.forEach((logger, level) -> {
                logger.detachAppender(appender);
                logger.setLevel(level);
            });
            appender.stop();
            jdbc
                    .execute(
                            "TRUNCATE core.credential, core.cryptographic_key, core.attribute_definition, core.certificate_request, core.certificate_content CASCADE");
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {4, 5})
    void proofReportStopsCountDriftBetweenActualPostgresPagesBeforeMoreHealthReads(int initialCount) throws Exception {
        var inventory = new java.util.ArrayList<UUID>();
        for (int i = 0; i < initialCount; i++) {
            var certificate = certificate(profile, "drift-" + i + ".synthetic");
            inventory.add(certificate.getUuid());
            jdbc
                    .update("UPDATE core.certificate SET i_cre=? WHERE uuid=?",
                            java.time.LocalDateTime.of(2026, java.time.Month.OCTOBER, 27, 0, initialCount - i),
                            certificate.getUuid());
        }
        AUTHORITY.principal = principal(ACTOR, profile, inventory, List.of(), List.of());
        authenticateCachedActor();
        var scope = new CertificateReadScope(profile.getUuid(), Set.copyOf(inventory));
        var pageSelections = new AtomicInteger();
        var healthReads = new AtomicInteger();
        var fixtureUpdates = new AtomicInteger();
        var published = new AtomicReference<CertificateReadProofAdapter.Report>();
        var failure = new AtomicReference<IllegalStateException>();
        try (var writer = java.util.Objects.requireNonNull(jdbc.getDataSource()).getConnection();
                var archive = writer.prepareStatement("UPDATE core.certificate SET archived=true WHERE uuid=?")) {
            writer.setAutoCommit(false);
            archive.setObject(1, inventory.getFirst());
            var captured = SqlCapture.during(() -> {
                try {
                    published
                            .set(invocation
                                    .call(ACTOR, scope, INVOCATION_TIMEOUT,
                                            () -> proofAdapter()
                                                    .report(new CertificateReadProofAdapter.SearchArguments(1, 2, null,
                                                            null, null))));
                } catch (IllegalStateException unavailable) {
                    failure.set(unavailable);
                }
                return true;
            }, sql -> {
                if (sql.contains("substr(")) {
                    healthReads.incrementAndGet();
                }
                if (sql.matches("select \\w+\\.uuid from core\\.certificate .*")
                        && pageSelections.incrementAndGet() == 2) {
                    try {
                        fixtureUpdates.set(archive.executeUpdate());
                        writer.commit();
                    } catch (java.sql.SQLException fixtureFailure) {
                        throw new AssertionError("External fixture writer failed");
                    }
                }
            });
            assertThat(fixtureUpdates.get()).as("one external committed fixture change between pages").isEqualTo(1);
            assertThat(pageSelections.get()).isEqualTo(2);
            boolean reportPublished = published.get() != null;
            assertThat(reportPublished).as("changed page inventory cannot publish a report").isFalse();
            assertThat(failure.get()).isNotNull().hasMessage("Certificate read unavailable").hasNoCause();
            assertThat(healthReads.get()).as("drift detected before second-page health reads").isEqualTo(2);
            assertThat(protectedSql(captured.statements())).hasSize(8);
            assertThat(captured.statements()).noneMatch(AiCertificateReadProofITest::isBusinessDml);
            assertNoNamedSinkCalls(eventProducer);
        }
    }

    @Test
    void proofReportTenPageBoundStopsBeforeAnotherAdvertisedPage() throws Exception {
        var all = new java.util.ArrayList<UUID>();
        all.add(allowed.getUuid());
        for (int i = 0; i < 10; i++) {
            all.add(certificate(profile, "bounded-" + i + ".synthetic").getUuid());
        }
        AUTHORITY.principal = principal(ACTOR, profile, all, List.of(), List.of());
        authenticateCachedActor();
        var captured = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, new CertificateReadScope(profile.getUuid(), Set.copyOf(all)),
                                Duration.ofSeconds(20),
                                () -> proofAdapter()
                                        .report(new CertificateReadProofAdapter.SearchArguments(1, 1, null, null,
                                                null))));
        assertThat(captured.result().pagesRead()).isEqualTo(10);
        assertThat(captured.result().certificates()).hasSize(10);
        assertThat(captured.result().observedTotal()).isEqualTo(11);
        assertThat(captured.result().allPagesRead()).isFalse();
        assertThat(captured.result().stoppedAtLimit()).isTrue();
        assertObservationsContract(captured.result());
        assertThat(protectedSql(captured.statements())).hasSize(40);
    }

    @Test
    void proofReportExpiredAfterReadCannotPublishAndRestoresCallerContexts() throws Exception {
        jdbc
                .update("UPDATE core.certificate SET certificate_validation_result=?,status_validation_timestamp=? WHERE uuid=?",
                        "{\"signature\":{\"status\":\"valid\"}}",
                        java.time.OffsetDateTime.parse("2026-10-27T00:00:00Z"), allowed.getUuid());
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var caller = SecurityContextHolder.getContext();
        var previousMdc = org.slf4j.MDC.getCopyOfContextMap();
        org.slf4j.MDC.put("proofCaller", "preserved");
        var mdc = org.slf4j.MDC.getCopyOfContextMap();
        var request = new org.springframework.web.context.request.ServletRequestAttributes(
                new org.springframework.mock.web.MockHttpServletRequest());
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(request);
        Clock slowClock = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                var context = AiReadInvocationContext.current().orElseThrow();
                org.awaitility.Awaitility.await().pollInSameThread().atMost(Duration.ofSeconds(5)).until(() -> {
                    try {
                        context.remainingAuthorityTimeout();
                        return false;
                    } catch (AccessDeniedException expired) {
                        return true;
                    }
                });
                return Instant.parse("2026-10-27T00:00:00Z");
            }
        };
        var published = new AtomicReference<CertificateReadProofAdapter.Report>();
        try {
            var captured = SqlCapture.during(() -> {
                assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> {
                    var report = new CertificateReadProofAdapter(service, slowClock)
                            .report(new CertificateReadProofAdapter.SearchArguments(1, 10, null, null, null));
                    published.set(report);
                    return report;
                })).isInstanceOf(AccessDeniedException.class);
                return true;
            });
            assertThat(protectedSql(captured.statements())).hasSize(4);
            assertThat(published.get()).isNull();
            assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
            assertThat(org.springframework.web.context.request.RequestContextHolder.getRequestAttributes())
                    .isSameAs(request);
            assertThat(org.slf4j.MDC.getCopyOfContextMap()).isEqualTo(mdc);
            assertThat(AiReadInvocationContext.isActive()).isFalse();
        } finally {
            if (previousMdc == null) {
                org.slf4j.MDC.clear();
            } else {
                org.slf4j.MDC.setContextMap(previousMdc);
            }
            org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes();
            request.requestCompleted();
        }
    }

    @Test
    void proofAdapterTypedOptionalFiltersConstrainActualSqlAndTimeBoundary() throws Exception {
        var boundary = Instant.parse("2026-10-27T00:00:00Z");
        jdbc
                .update("UPDATE core.certificate SET not_after=? WHERE uuid=?",
                        java.time.LocalDateTime.ofInstant(boundary.minusMillis(1), ZoneOffset.UTC), allowed.getUuid());
        jdbc
                .update("UPDATE core.certificate SET not_after=? WHERE uuid=?",
                        java.time.LocalDateTime.ofInstant(boundary, ZoneOffset.UTC), conflict.getUuid());
        var scope = new CertificateReadScope(profile.getUuid(), Set.of(allowed.getUuid(), conflict.getUuid()));
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid(), conflict.getUuid()), List.of(),
                List.of());
        authenticateCachedActor();
        var captured = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, scope, INVOCATION_TIMEOUT, () -> proofAdapter()
                                .dispatch(
                                        "{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":10,\"states\":[\"issued\"],\"validationStatuses\":[\"valid\"],\"expiresBefore\":\"2026-10-27T02:00:00+02:00\"}}")));
        assertThat(captured.result()).isInstanceOf(CertificateReadProofAdapter.SearchResult.class);
        var result = (CertificateReadProofAdapter.SearchResult) captured.result();
        assertThat(result.totalItems()).isEqualTo(1);
        assertThat(result.certificates())
                .singleElement()
                .satisfies(c -> assertThat(c.certificateUuid()).isEqualTo(allowed.getUuid()));
        assertThat(protectedSql(captured.statements())).hasSize(3);
        assertThat(protectedSql(captured.statements()).getFirst())
                .contains("not_after", "<timestamp '2026-10-27 00:00:00.000000'", "validation_status", "state");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "2026-10-27T00:00:00.000000001Z",
            "2026-10-27T00:00:00.123456789Z",
            "0000-01-01T00:00:00Z",
            "-0001-01-01T00:00:00Z",
            "+10000-01-01T00:00:00Z"})
    void proofAdapterRejectsLossyExpiryBeforeServiceOrSql(String expiry) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> proofAdapter()
                                .dispatch(
                                        "{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":10,\"expiresBefore\":\""
                                                + expiry + "\"}}")));
        assertThat(captured.result())
                .isEqualTo(new CertificateReadProofAdapter.Failure("Invalid certificate read arguments"));
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/v1/data/method")).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"outOfSet", "foreignProfile"})
    void proofAdapterStoredFailuresExcludeUntrustedTuples(String scenario) throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile,
                List.of(allowed.getUuid(), conflict.getUuid(), foreign.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        UUID requested = scenario.equals("outOfSet") ? conflict.getUuid() : foreign.getUuid();
        var scope = scenario.equals("foreignProfile")
                ? new CertificateReadScope(profile.getUuid(), Set.of(foreign.getUuid()))
                : readScope;
        AUTHORITY.exchanges.clear();
        var captured = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, scope, INVOCATION_TIMEOUT, () -> proofAdapter()
                                .dispatch("{\"tool\":\"certificate.storedHealth\",\"arguments\":{\"certificateUuid\":\""
                                        + requested + "\"}}")));
        assertThat(captured.result())
                .isEqualTo(new CertificateReadProofAdapter.Failure("Certificate read unavailable"));
        assertThat(protectedSql(captured.statements())).hasSize(scenario.equals("foreignProfile") ? 1 : 0);
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(scenario.equals("foreignProfile") ? 2 : 0);
    }

    @Test
    void proofReportRejectsStartingAfterPageOneBeforeServiceOrSql() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        AUTHORITY.exchanges.clear();
        var adapter = proofAdapter();
        var args = new CertificateReadProofAdapter.SearchArguments(2, 10, null, null, null);
        var captured = SqlCapture.during(() -> {
            assertThatThrownBy(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> adapter.report(args)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid certificate read arguments");
            return true;
        });
        assertNoProtectedOrAssociationSql(captured.statements());
        assertThat(AUTHORITY.count("/v1/data/method")).isZero();
    }

    @Test
    void proofAdapterMultiValueFiltersAndFilteredReportUseActualPredicates() throws Exception {
        jdbc
                .update("UPDATE core.certificate SET state='REVOKED',validation_status='EXPIRED' WHERE uuid=?",
                        conflict.getUuid());
        jdbc.update("UPDATE core.certificate SET validation_status='FAILED' WHERE uuid=?", owned.getUuid());
        jdbc.update("UPDATE core.certificate SET state='REQUESTED' WHERE uuid=?", grouped.getUuid());
        var selected = Set.of(allowed.getUuid(), conflict.getUuid(), owned.getUuid(), grouped.getUuid());
        var scope = new CertificateReadScope(profile.getUuid(), selected);
        AUTHORITY.principal = principal(ACTOR, profile, List.copyOf(selected), List.of(), List.of());
        authenticateCachedActor();
        var search = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, scope, INVOCATION_TIMEOUT, () -> proofAdapter()
                                .dispatch(
                                        "{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":10,\"states\":[\"issued\",\"revoked\"],\"validationStatuses\":[\"valid\",\"expired\"]}}")));
        assertThat(search.result()).isInstanceOf(CertificateReadProofAdapter.SearchResult.class);
        var result = (CertificateReadProofAdapter.SearchResult) search.result();
        assertThat(result.totalItems()).isEqualTo(2);
        assertThat(result.certificates().stream().map(CertificateReadProofAdapter.SafeCertificate::certificateUuid))
                .containsExactlyInAnyOrder(allowed.getUuid(), conflict.getUuid());
        assertThat(protectedSql(search.statements())).hasSize(3);
        assertThat(protectedSql(search.statements()).getFirst()).contains("state", "validation_status", " in (");
        var args = new CertificateReadProofAdapter.SearchArguments(1, 10,
                Set.of(CertificateState.ISSUED, CertificateState.REVOKED),
                Set.of(CertificateValidationStatus.VALID, CertificateValidationStatus.EXPIRED), null);
        var report = SqlCapture
                .during(() -> invocation.call(ACTOR, scope, INVOCATION_TIMEOUT, () -> proofAdapter().report(args)));
        assertThat(report.result().certificates().stream().map(entry -> entry.stored().certificateUuid()))
                .containsExactlyInAnyOrder(allowed.getUuid(), conflict.getUuid());
        assertThat(report.result().observedTotal()).isEqualTo(2);
        assertThat(report.result().allPagesRead()).isTrue();
        assertThat(report.result().stoppedAtLimit()).isFalse();
        assertObservationsContract(report.result());
        assertThat(protectedSql(report.statements())).hasSize(5);
        assertThat(report.statements()).noneMatch(AiCertificateReadProofITest::isBusinessDml);
        assertNoNamedSinkCalls(eventProducer);
    }

    @Test
    void proofReportZeroResultsReadTheOnlyAdvertisedInventoryWithoutHittingALimit() throws Exception {
        AUTHORITY.principal = principal(ACTOR, profile, List.of(allowed.getUuid()), List.of(), List.of());
        authenticateCachedActor();
        var args = new CertificateReadProofAdapter.SearchArguments(1, 10, Set.of(CertificateState.REQUESTED), null,
                null);
        var captured = SqlCapture
                .during(() -> invocation.call(ACTOR, readScope, INVOCATION_TIMEOUT, () -> proofAdapter().report(args)));
        assertThat(captured.result().certificates()).isEmpty();
        assertThat(captured.result().observedTotal()).isZero();
        assertThat(captured.result().pagesRead()).isEqualTo(1);
        assertThat(captured.result().allPagesRead()).isTrue();
        assertThat(captured.result().stoppedAtLimit()).isFalse();
        assertObservationsContract(captured.result());
        assertThat(protectedSql(captured.statements())).hasSize(2);
        assertNoNamedSinkCalls(eventProducer);
    }

    @Test
    void proofReportPublishesAtMostOneHundredRecords() throws Exception {
        var all = new java.util.ArrayList<UUID>();
        all.add(allowed.getUuid());
        for (int i = 0; i < 99; i++) {
            all.add(certificate(profile, "record-bound-" + i + ".synthetic").getUuid());
        }
        AUTHORITY.principal = principal(ACTOR, profile, all, List.of(), List.of());
        authenticateCachedActor();
        var captured = SqlCapture
                .during(() -> invocation
                        .call(ACTOR, new CertificateReadScope(profile.getUuid(), Set.copyOf(all)),
                                Duration.ofSeconds(30),
                                () -> proofAdapter()
                                        .report(new CertificateReadProofAdapter.SearchArguments(1, 100, null, null,
                                                null))));
        assertThat(captured.result().pagesRead()).isEqualTo(1);
        assertThat(captured.result().certificates()).hasSize(100);
        assertThat(captured.result().observedTotal()).isEqualTo(100);
        assertThat(captured.result().allPagesRead()).isTrue();
        assertThat(captured.result().stoppedAtLimit()).isFalse();
        assertObservationsContract(captured.result());
        assertThat(protectedSql(captured.statements())).hasSize(103);
    }

    private void assertObservationsContract(CertificateReadProofAdapter.Report report) {
        assertThat(report.evidenceBasis()).isEqualTo("OBSERVATIONS");
        var json = objectMapper.valueToTree(report);
        boolean claimsInventoryCompleteness = json.has("complete") || json.has("partial");
        assertThat(claimsInventoryCompleteness).as("observations have no inventory-completeness fields").isFalse();
    }

    private void seedReportSecrets(List<String> canaries) {
        UUID credential = UUID.randomUUID();
        UUID key = UUID.randomUUID();
        UUID request = UUID.randomUUID();
        jdbc
                .update("INSERT INTO core.credential(uuid,name,kind,enabled,i_cre,i_upd) VALUES (?,?,?,true,now(),now())",
                        credential, "Synthetic credential", "synthetic");
        jdbc
                .update("INSERT INTO core.cryptographic_key(uuid,name,i_cre,i_upd) VALUES (?, ?,now(),now())", key,
                        "Synthetic key");
        jdbc
                .update("INSERT INTO core.cryptographic_key_item(uuid,key_uuid,key_data,type,state,usage,enabled,exportable,compliance_status,created_at,updated_at) VALUES (?,?,?,'PRIVATE_KEY','ACTIVE',0,true,false,'NOT_CHECKED',now(),now())",
                        UUID.randomUUID(), key, canaries.get(1));
        jdbc
                .update("INSERT INTO core.certificate_request(uuid,certificate_type,certificate_request_format,fingerprint,content,key_usage,compliance_status,i_cre,i_upd) VALUES (?,'X509','PKCS10',?,?,0,'NOT_CHECKED',now(),now())",
                        request, UUID.randomUUID().toString(), canaries.get(8));
        jdbc
                .update("UPDATE core.certificate SET key_uuid=?,certificate_request_uuid=?,pending_revoke_attributes=?::jsonb, compliance_result=?::jsonb WHERE uuid=?",
                        key, request, "[{\"uuid\":\"" + UUID.randomUUID() + "\",\"content\":[{\"data\":\""
                                + canaries.get(3) + "\"}]}]",
                        "{\"synthetic\":\"" + canaries.get(5) + "\"}", allowed.getUuid());
        jdbc
                .update("INSERT INTO core.certificate_registration(uuid,certificate_uuid,meta,i_cre,i_upd) VALUES (?,?,?,now(),now())",
                        UUID.randomUUID(), allowed.getUuid(), "[]");
        jdbc
                .update("INSERT INTO core.certificate_registration_authorization(uuid,certificate_uuid,challenge,failed_attempts,state,i_cre,i_upd) VALUES (?,?,?,0,'ACTIVE',now(),now())",
                        UUID.randomUUID(), allowed.getUuid(), canaries.get(2));
        jdbc
                .update("INSERT INTO core.certificate_status_poll(uuid,certificate_uuid,operation,attempt,next_poll_at,i_cre) VALUES (?,?,'ISSUE',0,now(),now())",
                        UUID.randomUUID(), allowed.getUuid());
        jdbc
                .update("INSERT INTO core.certificate_event_history(uuid,certificate_uuid,message,i_cre,i_upd) VALUES (?,?,?,now(),now())",
                        UUID.randomUUID(), allowed.getUuid(), canaries.get(7));
        for (int index : List.of(0, 4)) {
            UUID definition = UUID.randomUUID();
            UUID content = UUID.randomUUID();
            jdbc
                    .update("INSERT INTO core.attribute_definition(uuid,attribute_uuid,name,type,label,visible,version,definition,created_at,updated_at) VALUES (?,?,?,'CUSTOM',?,true,3,'{}'::jsonb,now(),now())",
                            definition, UUID.randomUUID(), "Synthetic-" + index, "Synthetic");
            jdbc
                    .update("INSERT INTO core.attribute_content_item(uuid,attribute_definition_uuid,json,encrypted_data) VALUES (?,?,'[]'::jsonb,?)",
                            content, definition, canaries.get(index));
            jdbc
                    .update("INSERT INTO core.attribute_content_2_object(uuid,attribute_content_item_uuid,object_type,object_uuid,item_order,purpose) VALUES (?,?,?,?,0,?)",
                            UUID.randomUUID(), content, index == 0 ? "CREDENTIAL" : "CERTIFICATE",
                            index == 0 ? credential : allowed.getUuid(), "synthetic");
        }
    }

    private StoredCertificateHealth storedAllowed() throws com.otilm.api.exception.NotFoundException {
        return service
                .getStoredCertificateHealth(SecuredParentUUID.fromUUID(profile.getUuid()),
                        SecuredUUID.fromUUID(allowed.getUuid()));
    }

    private CertificateReadProofAdapter proofAdapter() {
        return new CertificateReadProofAdapter(service,
                Clock.fixed(Instant.parse("2026-10-27T00:00:00Z"), ZoneOffset.UTC));
    }

    private Map<String, List<String>> completeBusinessSnapshot() {
        var result = new java.util.TreeMap<String, List<String>>();
        var tables = jdbc
                .queryForList(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema='core' AND table_type='BASE TABLE' ORDER BY table_name",
                        String.class);
        for (String table : tables) {
            if (!table.matches("[a-z_0-9]+")) {
                throw new IllegalStateException("Unexpected proof table identifier");
            }
            result
                    .put(table, jdbc
                            .queryForList(
                                    "SELECT to_jsonb(t)::text FROM core.\"" + table + "\" t ORDER BY to_jsonb(t)::text",
                                    String.class));
        }
        return Map.copyOf(result);
    }

    private static void assertNoNamedSinkCalls(Object... sinks) {
        for (Object sink : sinks) {
            int invocationCount = mockingDetails(sink).getInvocations().size();
            assertThat(invocationCount).as("named producer, connector or audit sink was not called").isZero();
        }
    }

    private static boolean isBusinessDml(String sql) {
        String normalized = sql.stripLeading().toLowerCase(java.util.Locale.ROOT);
        return normalized.startsWith("insert ") || normalized.startsWith("update ") || normalized.startsWith("delete ")
                || normalized.startsWith("merge ");
    }

    private static void assertNoProtectedOrAssociationSql(List<String> statements) {
        assertThat(protectedSql(statements)).isEmpty();
        assertThat(statements).noneMatch(sql -> sql.contains("owner_association") || sql.contains("group_association"));
    }

    private void assertMethodAndObjectGrant(OpaClient client, String principal, OpaRequestedResource request,
            OpaRequestDetails details) {
        assertThat(client.checkResourceAccess("method", request, principal, details).isAuthorized()).isTrue();
        assertThat(client.checkObjectAccess("objects", request, principal, details).getAllowedObjects())
                .containsExactly(allowed.getUuid().toString());
    }

    private String storedValidationStatus() {
        return jdbc
                .queryForObject("SELECT validation_status FROM core.certificate WHERE uuid = ?", String.class,
                        allowed.getUuid());
    }

    private void authenticateCachedActor() {
        var info = authenticationClient.authenticateByUserUuid(ACTOR);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }

    private List<UUID> list() {
        return service
                .listCertificates(SecurityFilter.create(), new CertificateSearchRequestDto())
                .getCertificates()
                .stream()
                .map(c -> UUID.fromString(c.getUuid()))
                .toList();
    }

    private RaProfile profile(String name) {
        RaProfile result = new RaProfile();
        result.setName(name);
        result.setEnabled(true);
        result.setValidationEnabled(false);
        return profiles.saveAndFlush(result);
    }

    private Certificate certificate(RaProfile raProfile, String name) {
        X509CertificateEntity result = new X509CertificateEntity();
        result.setCommonName(name);
        result.setSubjectDn("CN=" + name);
        result.setIssuerDn("CN=synthetic issuer");
        result.setSerialNumber(UUID.randomUUID().toString());
        result.setState(CertificateState.ISSUED);
        result.setValidationStatus(CertificateValidationStatus.VALID);
        result.setRaProfileUuid(raProfile.getUuid());
        return certificates.saveAndFlush(result);
    }

    private String principal(UUID actor, RaProfile raProfile, List<UUID> allow, List<UUID> deny, List<UUID> groupAllow)
            throws Exception {
        List<Map<String, Object>> objects = java.util.stream.Stream
                .concat(allow.stream(), deny.stream())
                .distinct()
                .map(uuid -> Map
                        .<String, Object>of("uuid", uuid.toString(), "allow",
                                allow.contains(uuid) ? List.of("list", "detail") : List.of(), "deny",
                                deny.contains(uuid) ? List.of("list", "detail") : List.of()))
                .toList();
        return JSON
                .writeValueAsString(Map
                        .of("user", Map.of("uuid", actor.toString(), "username", "synthetic-" + actor, "enabled", true),
                                "roles", List.of(), "permissions",
                                Map
                                        .of("allowAllResources", false, "resources", List
                                                .of(Map
                                                        .of("name", "certificates", "allowAllActions", false, "actions",
                                                                List.of(), "objects", objects),
                                                        Map
                                                                .of("name", "raProfiles", "allowAllActions", false,
                                                                        "actions", List.of(), "objects",
                                                                        List
                                                                                .of(Map
                                                                                        .of("uuid",
                                                                                                raProfile
                                                                                                        .getUuid()
                                                                                                        .toString(),
                                                                                                "allow",
                                                                                                List.of("members"),
                                                                                                "deny", List.of()))),
                                                        Map
                                                                .of("name", "groups", "allowAllActions", false,
                                                                        "actions", List.of(), "objects",
                                                                        groupAllow
                                                                                .stream()
                                                                                .map(uuid -> Map
                                                                                        .of("uuid", uuid.toString(),
                                                                                                "allow",
                                                                                                List.of("members"),
                                                                                                "deny", List.of()))
                                                                                .toList())))));
    }

    private static List<String> protectedSql(List<String> statements) {
        return statements
                .stream()
                .filter(sql -> sql.contains("from core.certificate ") || sql.startsWith("update core.certificate "))
                .toList();
    }
}

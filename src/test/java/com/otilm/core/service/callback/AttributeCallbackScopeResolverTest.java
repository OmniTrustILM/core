package com.otilm.core.service.callback;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeReferenceExpander;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

/**
 * Pins the per-kind scope-walk + the fail-closed per-object {@code <KIND>:DETAIL} authorization that runs BEFORE any
 * blob is loaded. Each scoped route must authorize every parent in its chain against the calling user; an unmapped
 * resource must fail closed rather than return an empty (default-allow-shaped) chain.
 */
class AttributeCallbackScopeResolverTest {

    private AttributeEngine attributeEngine;
    private AttributeReferenceExpander expander;
    private AuthorizationEnforcer authorizationEnforcer;
    private AuthorityInstanceReferenceRepository authorityRepo;
    private RaProfileRepository raProfileRepo;
    private TokenProfileRepository tokenProfileRepo;
    private EntityInstanceReferenceRepository entityRepo;
    private AttributeCallbackScopeResolver resolver;

    @BeforeEach
    void setUp() {
        attributeEngine = Mockito.mock(AttributeEngine.class);
        expander = Mockito.mock(AttributeReferenceExpander.class);
        authorizationEnforcer = Mockito.mock(AuthorizationEnforcer.class);
        authorityRepo = Mockito.mock(AuthorityInstanceReferenceRepository.class);
        raProfileRepo = Mockito.mock(RaProfileRepository.class);
        tokenProfileRepo = Mockito.mock(TokenProfileRepository.class);
        entityRepo = Mockito.mock(EntityInstanceReferenceRepository.class);
        resolver = new AttributeCallbackScopeResolver(attributeEngine, expander, authorizationEnforcer,
                authorityRepo, raProfileRepo, tokenProfileRepo, entityRepo);
    }

    private Connector connectorWithUuid() {
        Connector connector = Mockito.mock(Connector.class);
        Mockito.when(connector.getUuid()).thenReturn(UUID.randomUUID());
        return connector;
    }

    @Test
    void unmappedResourceFailsClosedNotEmptyChain() {
        // The sole caller rejects unsupported scoped routes before dispatch, so an unmapped resource here is a
        // wiring error. Returning an empty chain would be a default-allow shape; it must throw instead.
        assertThrows(ValidationException.class,
                () -> resolver.resolveScopeChain(Resource.DISCOVERY, UUID.randomUUID(), new HashSet<>()));
    }

    @Test
    void certificateIssuanceAuthorizesAuthorityThenRaProfile() throws Exception {
        UUID raProfileUuid = UUID.randomUUID();
        Connector connector = connectorWithUuid();
        AuthorityInstanceReference authority = Mockito.mock(AuthorityInstanceReference.class);
        Mockito.when(authority.getUuid()).thenReturn(UUID.randomUUID());
        Mockito.when(authority.getConnector()).thenReturn(connector);
        RaProfile raProfile = Mockito.mock(RaProfile.class);
        Mockito.when(raProfile.getUuid()).thenReturn(raProfileUuid);
        Mockito.when(raProfile.getAuthorityInstanceReference()).thenReturn(authority);
        Mockito.when(raProfileRepo.findByUuid(raProfileUuid)).thenReturn(Optional.of(raProfile));

        resolver.resolveScopeChain(Resource.CERTIFICATE, raProfileUuid, new HashSet<>());

        Mockito.verify(authorizationEnforcer).enforce(eq(Resource.AUTHORITY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
        Mockito.verify(authorizationEnforcer).enforce(eq(Resource.RA_PROFILE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }

    @Test
    void cryptographicKeyAuthorizesTokenInstanceThenTokenProfile() throws Exception {
        UUID tokenProfileUuid = UUID.randomUUID();
        Connector connector = connectorWithUuid();
        TokenInstanceReference tokenInstance = Mockito.mock(TokenInstanceReference.class);
        Mockito.when(tokenInstance.getUuid()).thenReturn(UUID.randomUUID());
        Mockito.when(tokenInstance.getConnector()).thenReturn(connector);
        TokenProfile tokenProfile = Mockito.mock(TokenProfile.class);
        Mockito.when(tokenProfile.getUuid()).thenReturn(tokenProfileUuid);
        Mockito.when(tokenProfile.getTokenInstanceReference()).thenReturn(tokenInstance);
        Mockito.when(tokenProfileRepo.findByUuid(tokenProfileUuid)).thenReturn(Optional.of(tokenProfile));

        resolver.resolveScopeChain(Resource.CRYPTOGRAPHIC_KEY, tokenProfileUuid, new HashSet<>());

        Mockito.verify(authorizationEnforcer).enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
        Mockito.verify(authorizationEnforcer).enforce(eq(Resource.TOKEN_PROFILE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }

    @Test
    void locationAuthorizesEntity() throws Exception {
        UUID entityUuid = UUID.randomUUID();
        Connector connector = connectorWithUuid();
        EntityInstanceReference entity = Mockito.mock(EntityInstanceReference.class);
        Mockito.when(entity.getUuid()).thenReturn(entityUuid);
        Mockito.when(entity.getConnector()).thenReturn(connector);
        Mockito.when(entityRepo.findByUuid(entityUuid)).thenReturn(Optional.of(entity));

        resolver.resolveScopeChain(Resource.LOCATION, entityUuid, new HashSet<>());

        Mockito.verify(authorizationEnforcer).enforce(eq(Resource.ENTITY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }
}

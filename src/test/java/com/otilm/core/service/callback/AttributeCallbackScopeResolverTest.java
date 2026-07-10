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

import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
        attributeEngine = mock(AttributeEngine.class);
        expander = mock(AttributeReferenceExpander.class);
        authorizationEnforcer = mock(AuthorizationEnforcer.class);
        authorityRepo = mock(AuthorityInstanceReferenceRepository.class);
        raProfileRepo = mock(RaProfileRepository.class);
        tokenProfileRepo = mock(TokenProfileRepository.class);
        entityRepo = mock(EntityInstanceReferenceRepository.class);
        resolver = new AttributeCallbackScopeResolver(attributeEngine, expander, authorizationEnforcer,
                authorityRepo, raProfileRepo, tokenProfileRepo, entityRepo);
    }

    private Connector connectorWithUuid() {
        Connector connector = mock(Connector.class);
        when(connector.getUuid()).thenReturn(UUID.randomUUID());
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
        AuthorityInstanceReference authority = mock(AuthorityInstanceReference.class);
        when(authority.getUuid()).thenReturn(UUID.randomUUID());
        when(authority.getConnector()).thenReturn(connector);
        RaProfile raProfile = mock(RaProfile.class);
        when(raProfile.getUuid()).thenReturn(raProfileUuid);
        when(raProfile.getAuthorityInstanceReference()).thenReturn(authority);
        when(raProfileRepo.findByUuid(raProfileUuid)).thenReturn(Optional.of(raProfile));

        resolver.resolveScopeChain(Resource.CERTIFICATE, raProfileUuid, new HashSet<>());

        verify(authorizationEnforcer).enforce(eq(Resource.AUTHORITY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
        verify(authorizationEnforcer).enforce(eq(Resource.RA_PROFILE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }

    @Test
    void cryptographicKeyAuthorizesTokenInstanceThenTokenProfile() throws Exception {
        UUID tokenProfileUuid = UUID.randomUUID();
        Connector connector = connectorWithUuid();
        TokenInstanceReference tokenInstance = mock(TokenInstanceReference.class);
        when(tokenInstance.getUuid()).thenReturn(UUID.randomUUID());
        when(tokenInstance.getConnector()).thenReturn(connector);
        TokenProfile tokenProfile = mock(TokenProfile.class);
        when(tokenProfile.getUuid()).thenReturn(tokenProfileUuid);
        when(tokenProfile.getTokenInstanceReference()).thenReturn(tokenInstance);
        when(tokenProfileRepo.findByUuid(tokenProfileUuid)).thenReturn(Optional.of(tokenProfile));

        resolver.resolveScopeChain(Resource.CRYPTOGRAPHIC_KEY, tokenProfileUuid, new HashSet<>());

        verify(authorizationEnforcer).enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
        verify(authorizationEnforcer).enforce(eq(Resource.TOKEN_PROFILE), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }

    @Test
    void locationAuthorizesEntity() throws Exception {
        UUID entityUuid = UUID.randomUUID();
        Connector connector = connectorWithUuid();
        EntityInstanceReference entity = mock(EntityInstanceReference.class);
        when(entity.getUuid()).thenReturn(entityUuid);
        when(entity.getConnector()).thenReturn(connector);
        when(entityRepo.findByUuid(entityUuid)).thenReturn(Optional.of(entity));

        resolver.resolveScopeChain(Resource.LOCATION, entityUuid, new HashSet<>());

        verify(authorizationEnforcer).enforce(eq(Resource.ENTITY), eq(ResourceAction.DETAIL), any(SecuredUUID.class));
    }
}

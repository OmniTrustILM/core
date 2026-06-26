package com.otilm.core.service.callback;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.attribute.ScopedAttributes;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeReferenceExpander;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * #1621 Task 5 — table-driven scope-chain resolver for NG attribute callbacks.
 *
 * <p>Replaces the hand-coded resource→object mapping with a table {@code Map<Resource, walker>}: each scoped
 * resource resolves to an ordered (parent-first) chain of scope objects, and each scope object is turned into
 * a {@link ScopedAttributes} blob carrying that object's connector-consumable data attributes.
 *
 * <p>Each blob's credential-bearing RESOURCE references are expanded via
 * {@link AttributeReferenceExpander#expandForCaller} — a callback is operator-triggered, so each scope object's
 * credential is authorized against the <em>calling user</em> (per-caller, per-object) and the call
 * <strong>fails closed</strong> if the operator lacks {@code <KIND>:DETAIL} on a parent. The operation-path
 * {@code expandAsSystem} is deliberately never reached from a callback.
 *
 * <p>Unknown / unmapped resources return an empty chain (the connector-scoped contract); the throwing default
 * for a truly-unmapped scoped route lives in {@code CallbackServiceImpl.resourceCallback}, not here.
 */
@Component
public class AttributeCallbackScopeResolver {

    private final AttributeEngine attributeEngine;
    private final AttributeReferenceExpander expander;
    private final AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    private final RaProfileRepository raProfileRepository;
    private final TokenProfileRepository tokenProfileRepository;
    private final EntityInstanceReferenceRepository entityInstanceReferenceRepository;

    private final Map<Resource, ScopeWalker> walkers = new EnumMap<>(Resource.class);

    /** A scope-chain walker that may fail with a 404 when a referenced object is absent. */
    @FunctionalInterface
    private interface ScopeWalker {
        List<ScopeStep> walk(UUID resourceUuid) throws NotFoundException;
    }

    public AttributeCallbackScopeResolver(AttributeEngine attributeEngine,
                                          AttributeReferenceExpander expander,
                                          AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository,
                                          RaProfileRepository raProfileRepository,
                                          TokenProfileRepository tokenProfileRepository,
                                          EntityInstanceReferenceRepository entityInstanceReferenceRepository) {
        this.attributeEngine = attributeEngine;
        this.expander = expander;
        this.authorityInstanceReferenceRepository = authorityInstanceReferenceRepository;
        this.raProfileRepository = raProfileRepository;
        this.tokenProfileRepository = tokenProfileRepository;
        this.entityInstanceReferenceRepository = entityInstanceReferenceRepository;
        registerWalkers();
    }

    /** A single scope object in a chain: its kind, its UUID, and the connector that owns its attributes. */
    public record ScopeStep(Resource kind, UUID objectUuid, UUID connectorUuid) {
    }

    private void registerWalkers() {
        walkers.put(Resource.RA_PROFILE, this::walkRaProfile);
        walkers.put(Resource.CERTIFICATE, this::walkCertificateIssuance);
        walkers.put(Resource.TOKEN_PROFILE, this::walkTokenProfile);
        walkers.put(Resource.CRYPTOGRAPHIC_KEY, this::walkCryptographicKey);
        walkers.put(Resource.LOCATION, this::walkLocation);
    }

    /**
     * Resolve the ordered (parent-first) scope chain for the given scoped resource into expanded
     * {@link ScopedAttributes} blobs. Unknown resource → empty list.
     */
    public List<ScopedAttributes> resolveScopeChain(Resource resource, UUID resourceUuid, Set<String> expandedSecrets)
            throws NotFoundException, AttributeException, ConnectorException {
        ScopeWalker walker = walkers.get(resource);
        if (walker == null) {
            return List.of();
        }
        List<ScopedAttributes> chain = new ArrayList<>();
        for (ScopeStep step : walker.walk(resourceUuid)) {
            chain.add(buildScopedAttributes(step, expandedSecrets));
        }
        return chain;
    }

    private ScopedAttributes buildScopedAttributes(ScopeStep step, Set<String> expandedSecrets)
            throws NotFoundException, AttributeException, ConnectorException {
        List<RequestAttribute> attributes = attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(step.kind(), step.objectUuid())
                        .connector(step.connectorUuid())
                        .build());
        // Per-caller, per-object authorization; mutates the list in place, expanding credential references. The
        // shared expandedSecrets accumulator lets the dispatcher reject a connector echoing any of these back (#1624).
        expander.expandForCaller(attributes, expandedSecrets);

        ScopedAttributes scoped = new ScopedAttributes();
        scoped.setScope(step.kind());
        scoped.setObjectUuid(step.objectUuid());
        scoped.setAttributes(attributes);
        return scoped;
    }

    // --- walkers ------------------------------------------------------------------------------------------

    private List<ScopeStep> walkRaProfile(UUID raProfileUuid) throws NotFoundException {
        AuthorityInstanceReference authority = authorityInstanceReferenceRepository.findByUuid(raProfileUuid)
                .orElseThrow(() -> notFound(AuthorityInstanceReference.class, raProfileUuid));
        return List.of(authorityStep(authority));
    }

    private List<ScopeStep> walkCertificateIssuance(UUID raProfileUuid) throws NotFoundException {
        RaProfile raProfile = raProfileRepository.findByUuid(raProfileUuid)
                .orElseThrow(() -> notFound(RaProfile.class, raProfileUuid));
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        if (authority == null) {
            return List.of(raProfileStep(raProfile));
        }
        return List.of(authorityStep(authority), raProfileStep(raProfile));
    }

    private List<ScopeStep> walkTokenProfile(UUID tokenProfileUuid) throws NotFoundException {
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(tokenProfileUuid)
                .orElseThrow(() -> notFound(TokenProfile.class, tokenProfileUuid));
        return List.of(tokenInstanceStep(tokenProfile));
    }

    private List<ScopeStep> walkCryptographicKey(UUID tokenProfileUuid) throws NotFoundException {
        TokenProfile tokenProfile = tokenProfileRepository.findByUuid(tokenProfileUuid)
                .orElseThrow(() -> notFound(TokenProfile.class, tokenProfileUuid));
        return List.of(tokenInstanceStep(tokenProfile), tokenProfileStep(tokenProfile));
    }

    private List<ScopeStep> walkLocation(UUID entityInstanceUuid) throws NotFoundException {
        EntityInstanceReference entity = entityInstanceReferenceRepository.findByUuid(entityInstanceUuid)
                .orElseThrow(() -> notFound(EntityInstanceReference.class, entityInstanceUuid));
        return List.of(new ScopeStep(Resource.ENTITY, entity.getUuid(),
                entity.getConnector() == null ? null : entity.getConnector().getUuid()));
    }

    private static ScopeStep authorityStep(AuthorityInstanceReference authority) {
        return new ScopeStep(Resource.AUTHORITY, authority.getUuid(),
                authority.getConnector() == null ? null : authority.getConnector().getUuid());
    }

    private static ScopeStep raProfileStep(RaProfile raProfile) {
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        UUID connectorUuid = authority == null || authority.getConnector() == null ? null : authority.getConnector().getUuid();
        return new ScopeStep(Resource.RA_PROFILE, raProfile.getUuid(), connectorUuid);
    }

    private static ScopeStep tokenInstanceStep(TokenProfile tokenProfile) {
        var tokenInstance = tokenProfile.getTokenInstanceReference();
        UUID connectorUuid = tokenInstance == null || tokenInstance.getConnector() == null ? null : tokenInstance.getConnector().getUuid();
        UUID tokenInstanceUuid = tokenInstance == null ? null : tokenInstance.getUuid();
        return new ScopeStep(Resource.TOKEN, tokenInstanceUuid, connectorUuid);
    }

    private static ScopeStep tokenProfileStep(TokenProfile tokenProfile) {
        var tokenInstance = tokenProfile.getTokenInstanceReference();
        UUID connectorUuid = tokenInstance == null || tokenInstance.getConnector() == null ? null : tokenInstance.getConnector().getUuid();
        return new ScopeStep(Resource.TOKEN_PROFILE, tokenProfile.getUuid(), connectorUuid);
    }

    private static NotFoundException notFound(Class<?> type, UUID uuid) {
        return new NotFoundException(type, uuid.toString());
    }
}

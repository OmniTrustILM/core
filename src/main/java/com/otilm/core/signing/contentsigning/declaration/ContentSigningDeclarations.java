package com.otilm.core.signing.contentsigning.declaration;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.ContentSigningDeclarationDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.dao.entity.ConnectorContentSigningDeclaration;
import com.otilm.core.dao.repository.ConnectorContentSigningDeclarationRepository;
import com.otilm.core.events.ConnectorChangedEvent;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.cache.CacheManager;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Stored content-signing declarations of formatting connectors, cached until the entry expires or the connector
 * changes.
 */
@Component
public class ContentSigningDeclarations {

    private final ConnectorContentSigningDeclarationRepository repository;
    private final CacheEvictor cacheEvictor;
    private final ReadThroughCache declarationCache;

    public ContentSigningDeclarations(ConnectorContentSigningDeclarationRepository repository,
            CacheManager cacheManager, CacheEvictor cacheEvictor) {
        this.repository = repository;
        this.cacheEvictor = cacheEvictor;
        this.declarationCache = ReadThroughCache.from(cacheManager, CacheConfig.CONTENT_SIGNING_DECLARATION_CACHE);
    }

    /** Families the connector declared, empty for a connector that serves no content signing. */
    public List<SignatureFamilyDeclarationDto> families(UUID connectorUuid) {
        return declaration(connectorUuid).map(ContentSigningDeclarationDto::getFamilies).orElse(List.of());
    }

    public Optional<SignatureFamilyDeclarationDto> family(UUID connectorUuid, SignatureFamily family) {
        return families(connectorUuid).stream().filter(declared -> family.equals(declared.getCode())).findFirst();
    }

    @EventListener
    public void forgetConnector(ConnectorChangedEvent changed) {
        cacheEvictor.evict(CacheConfig.CONTENT_SIGNING_DECLARATION_CACHE, changed.connectorUuid());
    }

    private Optional<ContentSigningDeclarationDto> declaration(UUID connectorUuid) {
        return declarationCache
                .getOrLoad(connectorUuid,
                        () -> repository
                                .findById(connectorUuid)
                                .map(ConnectorContentSigningDeclaration::getDeclaration));
    }
}

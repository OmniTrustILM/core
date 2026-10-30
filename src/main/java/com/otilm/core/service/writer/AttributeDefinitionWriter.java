package com.otilm.core.service.writer;

import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.serialization.AttributeDefinitionJson;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.UUID;
import org.hibernate.query.NativeQuery;
import org.hibernate.type.StandardBasicTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AttributeDefinitionWriter {

    private static final String INSERT_IF_ABSENT = """
            INSERT INTO {h-schema}attribute_definition (uuid, connector_uuid, attribute_uuid, name, type, content_type,
                label, required, read_only, visible, version, definition, global, operation, protection_level,
                created_at, updated_at)
            VALUES (:uuid, :connectorUuid, :attributeUuid, :name, :type, :contentType, :label, :required, :readOnly,
                :visible, :version, CAST(:definition AS jsonb), :global, :operation, :protectionLevel, :now, :now)
            ON CONFLICT DO NOTHING
            """;

    private final AttributeDefinitionRepository attributeDefinitionRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    public AttributeDefinitionWriter(AttributeDefinitionRepository attributeDefinitionRepository) {
        this.attributeDefinitionRepository = attributeDefinitionRepository;
    }

    /** Returns whether this call set the operation of a definition that had none. */
    @Transactional
    public boolean claimOperation(UUID definitionUuid, String operation) {
        return attributeDefinitionRepository.claimOperation(definitionUuid, operation) == 1;
    }

    /**
     * Stores a new definition unless one with the same key (the connector's attribute or the global name) exists; a
     * concurrent writer of the same key makes this wait, then write nothing. Either key counts: there is no conflict
     * target.
     *
     * <p>
     * Declares {@link AttributeDefinition} and {@link Connector} as its tables, so a pending definition or connector is
     * flushed first and the connector foreign key holds; a flush, once triggered, runs the session's whole action
     * queue.
     *
     * @return whether this call stored the definition
     */
    @Transactional
    public boolean insertIfAbsent(AttributeDefinition definition) {
        LocalDateTime now = LocalDateTime.now(ZoneId.systemDefault());
        NativeQuery<?> insert = entityManager.createNativeQuery(INSERT_IF_ABSENT).unwrap(NativeQuery.class);
        return insert
                .addSynchronizedEntityClass(AttributeDefinition.class)
                .addSynchronizedEntityClass(Connector.class)
                .setParameter("uuid", UUID.randomUUID(), StandardBasicTypes.UUID)
                .setParameter("connectorUuid", definition.getConnectorUuid(), StandardBasicTypes.UUID)
                .setParameter("attributeUuid", definition.getAttributeUuid(), StandardBasicTypes.UUID)
                .setParameter("name", definition.getName(), StandardBasicTypes.STRING)
                .setParameter("type", definition.getType().name(), StandardBasicTypes.STRING)
                .setParameter("contentType",
                        definition.getContentType() == null ? null : definition.getContentType().name(),
                        StandardBasicTypes.STRING)
                .setParameter("label", definition.getLabel(), StandardBasicTypes.STRING)
                .setParameter("required", definition.isRequired(), StandardBasicTypes.BOOLEAN)
                .setParameter("readOnly", definition.isReadOnly(), StandardBasicTypes.BOOLEAN)
                .setParameter("visible", definition.isVisible(), StandardBasicTypes.BOOLEAN)
                .setParameter("version", definition.getVersion(), StandardBasicTypes.INTEGER)
                .setParameter("definition", AttributeDefinitionJson.render(definition.getDefinition()),
                        StandardBasicTypes.STRING)
                .setParameter("global", definition.getGlobal(), StandardBasicTypes.BOOLEAN)
                .setParameter("operation", definition.getOperation(), StandardBasicTypes.STRING)
                .setParameter("protectionLevel",
                        definition.getProtectionLevel() == null ? null : definition.getProtectionLevel().name(),
                        StandardBasicTypes.STRING)
                .setParameter("now", now, StandardBasicTypes.LOCAL_DATE_TIME)
                .executeUpdate() == 1;
    }
}

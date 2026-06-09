package com.czertainly.core.attribute.engine.records;

import com.otilm.api.model.core.auth.Resource;

import java.util.Objects;
import java.util.UUID;

public record ObjectAttributeContentInfo(
        UUID connectorUuid,
        Resource objectType,
        UUID objectUuid,
        Resource sourceObjectType,
        UUID sourceObjectUuid,
        String sourceObjectName,
        String purpose,
        Integer objectVersion,
        String operation
) {
    public ObjectAttributeContentInfo {
        Objects.requireNonNull(objectType);
        Objects.requireNonNull(objectUuid);
    }

    public static Builder builder(Resource objectType, UUID objectUuid) {
        return new Builder(objectType, objectUuid);
    }

    public static final class Builder {
        private final Resource objectType;
        private final UUID objectUuid;
        private UUID connectorUuid;
        private Resource sourceObjectType;
        private UUID sourceObjectUuid;
        private String sourceObjectName;
        private String purpose;
        private Integer objectVersion;
        private String operation;

        private Builder(Resource objectType, UUID objectUuid) {
            this.objectType = Objects.requireNonNull(objectType);
            this.objectUuid = Objects.requireNonNull(objectUuid);
        }

        public Builder connector(UUID connectorUuid) {
            this.connectorUuid = connectorUuid;
            return this;
        }

        public Builder operation(String operation) {
            this.operation = operation;
            return this;
        }

        public Builder purpose(String purpose) {
            this.purpose = purpose;
            return this;
        }

        public Builder version(Integer objectVersion) {
            this.objectVersion = objectVersion;
            return this;
        }

        public Builder source(Resource sourceObjectType, UUID sourceObjectUuid) {
            this.sourceObjectType = sourceObjectType;
            this.sourceObjectUuid = sourceObjectUuid;
            return this;
        }

        public Builder sourceName(String sourceObjectName) {
            this.sourceObjectName = sourceObjectName;
            return this;
        }

        public ObjectAttributeContentInfo build() {
            return new ObjectAttributeContentInfo(
                    connectorUuid, objectType, objectUuid,
                    sourceObjectType, sourceObjectUuid, sourceObjectName,
                    purpose, objectVersion, operation);
        }
    }
}

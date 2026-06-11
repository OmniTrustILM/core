package com.otilm.core.dao.entity;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.core.protocol.ProtocolCertificateAssociationsDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.function.TriFunction;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.List;
import java.util.UUID;

@Entity
@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
public class ProtocolCertificateAssociations extends UniquelyIdentified {

    @Column
    private UUID ownerUuid;

    @Column
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<UUID> groupUuids;

    @Column(columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<RequestAttribute> customAttributes;

    public ProtocolCertificateAssociationsDto mapToDto(TriFunction<AttributeType, UUID, List<RequestAttribute>, List<ResponseAttribute>> convertAttributesFunc) {
        ProtocolCertificateAssociationsDto dto = new ProtocolCertificateAssociationsDto();
        dto.setCustomAttributes(convertAttributesFunc.apply(AttributeType.CUSTOM, null, customAttributes));
        dto.setGroupUuids(groupUuids);
        dto.setOwnerUuid(ownerUuid);
        return dto;
    }


}

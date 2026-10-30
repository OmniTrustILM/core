package com.otilm.core.dao.entity.workflows;

import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ConditionItemDto;
import com.otilm.core.dao.converter.ObjectToJsonConverter;
import com.otilm.core.dao.entity.ComplianceInternalRule;
import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.Objects;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "condition_item")
public class ConditionItem extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "condition_uuid")
    @ToString.Exclude
    private Condition condition;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "compliance_internal_rule_uuid")
    @ToString.Exclude
    private ComplianceInternalRule complianceInternalRule;

    @Column(name = "field_source", nullable = false)
    @Enumerated(EnumType.STRING)
    private FilterFieldSource fieldSource;

    @Column(name = "field_identifier", nullable = false)
    private String fieldIdentifier;

    @Column(name = "operator", nullable = false)
    @Enumerated(EnumType.STRING)
    private FilterConditionOperator operator;

    @Column(name = "value", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Convert(converter = ObjectToJsonConverter.class)
    private Object value;

    public ConditionItemDto mapToDto() {
        ConditionItemDto conditionItemDto = new ConditionItemDto();
        conditionItemDto.setFieldSource(fieldSource);
        conditionItemDto.setFieldIdentifier(fieldIdentifier);
        conditionItemDto.setOperator(operator);
        conditionItemDto.setValue(value);

        return conditionItemDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        if (!(o instanceof ConditionItem that)) {
            return false;
        }
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}

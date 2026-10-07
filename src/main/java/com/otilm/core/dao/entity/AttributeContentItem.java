package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
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
@Table(name = "attribute_content_item", uniqueConstraints = @UniqueConstraint(name = "uq_attribute_content_item_value",
        columnNames = {"attribute_definition_uuid", "json_hash"}))
public class AttributeContentItem extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "attribute_definition_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private AttributeDefinition attributeDefinition;

    @Column(name = "attribute_definition_uuid", nullable = false)
    private UUID attributeDefinitionUuid;

    @Column(name = "json", nullable = false, columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private AttributeContent json;

    @JsonBackReference
    @OneToMany(mappedBy = "attributeContentItem", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<AttributeContent2Object> objects;

    @Column(name = "encrypted_data", length = Integer.MAX_VALUE)
    private String encryptedData;

    /**
     * Computed by the database, and mapped only so the test schema — generated from these annotations — carries the
     * column the insert's conflict target names. Follows jsonb equality, as the lookup by value does. NULL for an
     * encrypted row: its value lives in salted ciphertext, so equal values never share a json and stay one row per
     * object, and NULLs never collide. A hash keeps the index entry inside the btree limit, and jsonb_hash_extended
     * rather than a cryptographic digest, which a FIPS-mode server may refuse to compute.
     */
    @Column(name = "json_hash",
            columnDefinition = "bigint generated always as (case when encrypted_data is null then jsonb_hash_extended(json, 0) end) stored",
            insertable = false, updatable = false)
    private Long jsonHash;

    public void setAttributeDefinition(AttributeDefinition attributeDefinition) {
        this.attributeDefinition = attributeDefinition;
        this.attributeDefinitionUuid = attributeDefinition.getUuid();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy
                ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        AttributeContentItem that = (AttributeContentItem) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}

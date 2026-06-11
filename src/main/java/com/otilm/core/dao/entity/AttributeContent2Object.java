package com.otilm.core.dao.entity;

import com.otilm.api.model.core.auth.Resource;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "attribute_content_2_object")
public class AttributeContent2Object extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "attribute_content_item_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private AttributeContentItem attributeContentItem;

    @Column(name = "attribute_content_item_uuid", nullable = false)
    private UUID attributeContentItemUuid;

    @Column(name = "object_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource objectType;

    @Column(name = "object_uuid", nullable = false)
    private UUID objectUuid;

    @Column(name = "source_object_type")
    @Enumerated(EnumType.STRING)
    private Resource sourceObjectType;

    @Column(name = "source_object_uuid")
    private UUID sourceObjectUuid;

    @Column(name = "source_object_name")
    private String sourceObjectName;

    @Column(name = "item_order")
    private int order;

    @Column(name = "purpose")
    private String purpose;

    @Column(name = "object_version")
    private Integer objectVersion;

    public void setConnector(Connector connector) {
        this.connector = connector;
        if (connector != null) this.connectorUuid = connector.getUuid();
    }

    public void setAttributeContentItem(AttributeContentItem attributeContentItem) {
        this.attributeContentItem = attributeContentItem;
        this.attributeContentItemUuid = attributeContentItem.getUuid();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        AttributeContent2Object that = (AttributeContent2Object) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}

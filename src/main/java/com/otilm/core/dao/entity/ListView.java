package com.otilm.core.dao.entity;

import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewFilterDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A named set of columns, filters and ordering that one user has saved for one listing. The owning user is a bare UUID
 * with no foreign key - users live in the identity service - so the rows are removed where the platform learns of the
 * deletion, in {@link com.otilm.core.service.UserManagementExternalService#deleteUser(String)}.
 *
 * <p>
 * Fields are stored by identifier, so a renamed or deleted attribute leaves its column or filter dormant instead of
 * requiring stored rows to be migrated. An attribute column or filter also stores the definitions it was bound to, so a
 * definition created later under the same identifier does not take it over.
 */
@Setter
@Getter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "list_view", uniqueConstraints = @UniqueConstraint(name = ListView.UNIQUE_NAME_CONSTRAINT,
        columnNames = {"user_uuid", "resource", "name"}))
public class ListView extends UniquelyIdentifiedAndAudited {

    public static final String UNIQUE_NAME_CONSTRAINT = "uk_list_view_user_resource_name";

    @Column(name = "user_uuid", nullable = false, updatable = false)
    private UUID userUuid;

    @Column(name = "resource", nullable = false, updatable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @Column(name = "name", nullable = false, length = 255)
    private String name;

    @Column(name = "default_view", nullable = false)
    private boolean defaultView;

    // S1948: entities are Serializable through UniquelyIdentifiedObject, but nothing Java-serializes them - Jackson
    // owns the persistence shape of these JSONB fields.
    @SuppressWarnings("java:S1948")
    @Column(name = "columns", nullable = false, columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<ListViewColumnDto> columns;

    @SuppressWarnings("java:S1948")
    @Column(name = "filters", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<ListViewFilterDto> filters;

    @SuppressWarnings("java:S1948")
    @Column(name = "sort", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private SearchSortRequestDto sort;

    /** The binding of an attribute ordering, kept beside it because the ordering's own shape is the listing's. */
    @SuppressWarnings("java:S1948")
    @Column(name = "sort_attribute_definition_uuids", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<UUID> sortAttributeDefinitionUuids;

    // No-op overrides required by S2160: identity and hashing stay UUID-based, and the added columns never
    // affect equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}

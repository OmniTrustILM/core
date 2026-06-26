package com.otilm.core.dao.entity.oid;

import com.otilm.api.model.core.oid.OidCategory;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Inheritance
@DiscriminatorColumn(name = "category")
@Getter
@Setter
public class CustomOidEntry {

    @Id
    @Column(name = "oid", nullable = false, updatable = false)
    private String oid;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "description")
    private String description;

    @Column(name = "category", nullable = false, insertable = false, updatable = false)
    @Enumerated(EnumType.STRING)
    private OidCategory category;

}

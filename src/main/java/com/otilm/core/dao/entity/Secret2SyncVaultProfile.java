package com.otilm.core.dao.entity;

import com.otilm.api.model.client.attribute.RequestAttribute;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "secret_2_sync_vault_profile")
@Getter
@Setter
public class Secret2SyncVaultProfile implements Serializable {

    @EmbeddedId
    private Secret2SyncVaultProfileId id = new Secret2SyncVaultProfileId();

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("secretUuid")
    @JoinColumn(name = "secret_uuid")
    private Secret secret;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("vaultProfileUuid")
    @JoinColumn(name = "vault_profile_uuid")
    private VaultProfile vaultProfile;

    @Column(name = "secret_attributes", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<RequestAttribute> secretAttributes = new ArrayList<>();

}

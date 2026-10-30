package com.otilm.core.dao.entity;

import com.otilm.api.model.client.attribute.RequestAttribute;
import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

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

package com.czertainly.core.dao.entity.signing;

import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.service.model.Securable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "signing_profile")
public class SigningProfile extends UniquelyIdentifiedAndAudited implements Securable {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled = false;

    /**
     * Denormalized cache column — mirrors the latest {@link SigningProfileVersion#signingScheme}.
     * Updated on every create/update alongside the version row.
     */
    @Column(name = "signing_scheme", nullable = false)
    @Enumerated(EnumType.STRING)
    private SigningScheme signingScheme;

    /**
     * Denormalized cache column — mirrors the latest {@link SigningProfileVersion#workflowType}.
     * Updated on every create/update alongside the version row.
     */
    @Column(name = "workflow_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private SigningWorkflowType workflowType;

    @Column(name = "latest_version", nullable = false)
    private Integer latestVersion = 1;

    @Column(name = "retention_days")
    private Integer retentionDays;

    @Column(name = "delete_after_retrieval", nullable = false)
    private boolean deleteAfterRetrieval = false;

    @Column(name = "persistence_mode", nullable = false)
    @Enumerated(EnumType.STRING)
    private SigningRecordPersistenceMode persistenceMode = SigningRecordPersistenceMode.DEFERRED_DURABLE;

    @Column(name = "record_metadata", nullable = false)
    private boolean recordMetadata = false;

    @Column(name = "record_request_metadata", nullable = false)
    private boolean recordRequestMetadata = false;

    @Column(name = "record_signature", nullable = false)
    private boolean recordSignature = false;

    @Column(name = "record_signed_document", nullable = false)
    private boolean recordSignedDocument = false;

    @Column(name = "record_dtbs", nullable = false)
    private boolean recordDtbs = false;

    @Column(name = "time_quality_config_uuid")
    private UUID timeQualityConfigurationUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "time_quality_config_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TimeQualityConfiguration timeQualityConfiguration;

    @Column(name = "tsp_profile_uuid")
    private UUID tspProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tsp_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private TspProfile tspProfile;

    @OneToMany(mappedBy = "signingProfile", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<SigningProfileVersion> versions = new ArrayList<>();

    @OneToMany(mappedBy = "signingProfile", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<SigningRecord> signingRecords = new ArrayList<>();

    public void setTimeQualityConfiguration(TimeQualityConfiguration timeQualityConfiguration) {
        this.timeQualityConfiguration = timeQualityConfiguration;
        this.timeQualityConfigurationUuid = timeQualityConfiguration != null ? timeQualityConfiguration.getUuid() : null;
    }

    public void setTspProfile(TspProfile tspProfile) {
        this.tspProfile = tspProfile;
        this.tspProfileUuid = tspProfile != null ? tspProfile.getUuid() : null;
    }
}

package com.otilm.core.dao.entity.notifications;

import com.otilm.core.dao.entity.UniquelyIdentified;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;
import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification_profile")
public class NotificationProfile extends UniquelyIdentified {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Version
    @Column(name = "version_lock", nullable = false)
    private int versionLock;  // Optimistic locking

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    protected OffsetDateTime createdAt;

    @ToString.Exclude
    @JsonBackReference
    @OneToMany(mappedBy = "notificationProfile", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @OrderBy("version DESC")
    private List<NotificationProfileVersion> versions = new ArrayList<>();

    @JsonBackReference
    public NotificationProfileVersion getCurrentVersion() {
        return versions.isEmpty() ? null : versions.getFirst();
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}

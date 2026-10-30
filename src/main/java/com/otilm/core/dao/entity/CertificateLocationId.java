package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Embedded class for a composite primary key
 */
@Setter
@Getter
@ToString
@RequiredArgsConstructor
@AllArgsConstructor
@Embeddable
public class CertificateLocationId implements Serializable {

    @Column(name = "location_uuid")
    private UUID locationUuid;

    @Column(name = "certificate_uuid")
    private UUID certificateUuid;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CertificateLocationId that)) {
            return false;
        }
        return Objects.equals(locationUuid, that.locationUuid) && Objects.equals(certificateUuid, that.certificateUuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(locationUuid, certificateUuid);
    }

}

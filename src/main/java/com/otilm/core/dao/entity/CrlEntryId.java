package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;
import java.util.UUID;

/**
 * Embedded class for a composite primary key
 */
@Getter
@Setter
@ToString
@RequiredArgsConstructor
@AllArgsConstructor
@Embeddable
public class CrlEntryId implements Serializable {

    @Column(name = "crl_uuid", nullable = false)
    private UUID crlUuid;

    @Column(name = "serial_number", nullable = false)
    private String serialNumber;

}

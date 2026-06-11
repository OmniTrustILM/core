package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventHistoryDto;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.core.util.DtoMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@EntityListeners(AuditingEntityListener.class)
@Entity
@Table(name = "certificate_event_history")
public class CertificateEventHistory extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<CertificateEventHistoryDto> {

    @Enumerated(EnumType.STRING)
    @Column(name = "event")
    private CertificateEvent event;

    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private CertificateEventStatus status;

    @Column(name="message", columnDefinition = "TEXT")
    private String message;

    @Column(name="additional_information", columnDefinition = "TEXT")
    private String additionalInformation;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private Certificate certificate;

    @Column(name = "certificate_uuid", nullable = false)
    private UUID certificateUuid;

    @Override
    public CertificateEventHistoryDto mapToDto(){
        CertificateEventHistoryDto certificateEventHistoryDto = new CertificateEventHistoryDto();
        certificateEventHistoryDto.setCertificateUuid(certificate.getUuid().toString());
        certificateEventHistoryDto.setEvent(event);
        try {
            certificateEventHistoryDto.setAdditionalInformation(
                    new ObjectMapper().readValue(additionalInformation, new TypeReference<>() {})
            );
        } catch (JsonProcessingException | IllegalArgumentException e) {
            certificateEventHistoryDto.setAdditionalInformation(null);
        }
        certificateEventHistoryDto.setUuid(uuid.toString());
        certificateEventHistoryDto.setMessage(message);
        certificateEventHistoryDto.setCreated(created);
        certificateEventHistoryDto.setCreatedBy(author);
        certificateEventHistoryDto.setStatus(status);
        return certificateEventHistoryDto;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
        this.certificateUuid = certificate.getUuid();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CertificateEventHistory that = (CertificateEventHistory) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}

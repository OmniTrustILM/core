package com.otilm.core.dao.entity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventHistoryDto;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.util.DtoMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "key_event_history")
public class CryptographicKeyEventHistory extends UniquelyIdentifiedAndAudited
        implements
            Serializable,
            DtoMapper<KeyEventHistoryDto> {

    @Enumerated(EnumType.STRING)
    @Column(name = "event")
    private KeyEvent event;

    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private KeyEventStatus status;

    @Column(name = "message")
    private String message;

    @Column(name = "additional_information", columnDefinition = "TEXT")
    private String additionalInformation;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private CryptographicKeyItem key;

    @Column(name = "key_uuid", nullable = false)
    private UUID keyUuid;

    @Override
    public KeyEventHistoryDto mapToDto() {
        KeyEventHistoryDto keyEventHistoryDto = new KeyEventHistoryDto();
        keyEventHistoryDto.setKeyUuid(key.getUuid().toString());
        keyEventHistoryDto.setEvent(event);
        try {
            keyEventHistoryDto
                    .setAdditionalInformation(
                            ObjectMapperFactory.storage().readValue(additionalInformation, new TypeReference<>() {
                            }));
        } catch (JsonProcessingException | IllegalArgumentException e) {
            keyEventHistoryDto.setAdditionalInformation(null);
        }
        keyEventHistoryDto.setMessage(message);
        keyEventHistoryDto.setUuid(uuid.toString());
        keyEventHistoryDto.setCreated(created);
        keyEventHistoryDto.setCreatedBy(author);
        keyEventHistoryDto.setStatus(status);
        return keyEventHistoryDto;
    }

    public void setKey(CryptographicKeyItem key) {
        this.key = key;
        if (key != null) {
            this.setKeyUuid(key.getUuid());
        }
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy
                ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        CryptographicKeyEventHistory that = (CryptographicKeyEventHistory) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}

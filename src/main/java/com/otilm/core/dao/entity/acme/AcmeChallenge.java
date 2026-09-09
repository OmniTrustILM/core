package com.otilm.core.dao.entity.acme;

import com.otilm.api.model.core.acme.Challenge;
import com.otilm.api.model.core.acme.ChallengeStatus;
import com.otilm.api.model.core.acme.ChallengeType;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.acme.ProblemDocument;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.util.AcmeCommonHelper;
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
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "acme_challenge")
public class AcmeChallenge extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<Challenge> {

    @Column(name = "challenge_id")
    private String challengeId;

    @Column(name = "type")
    @Enumerated(EnumType.STRING)
    private ChallengeType type;

    @Column(name = "token")
    private String token;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private ChallengeStatus status;

    @Column(name = "validated")
    private OffsetDateTime validated;

    @Column(name = "error_problem")
    @Enumerated(EnumType.STRING)
    private Problem errorProblem;

    @Column(name = "error_detail", length = Integer.MAX_VALUE)
    private String errorDetail;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "authorization_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private AcmeAuthorization authorization;

    @Column(name = "authorization_uuid", nullable = false)
    private UUID authorizationUuid;

    @Override
    public Challenge mapToDto() {
        Challenge challenge = new Challenge();
        challenge.setStatus(status);
        challenge.setToken(token);
        challenge.setType(type);
        challenge.setUrl(getUrl());
        challenge.setValidated(AcmeCommonHelper.getStringFromDate(validated));
        challenge.setError(mapErrorToDto());
        return challenge;
    }

    /**
     * Reason of a failed validation, as the problem document the client reads back.
     *
     * <p>
     * The {@link Problem} constants are shared and carry a mutable detail, so the recorded detail is set on the
     * document rather than on the constant.
     */
    private ProblemDocument mapErrorToDto() {
        if (errorProblem == null) {
            return null;
        }
        ProblemDocument error = new ProblemDocument(errorProblem);
        error.setDetail(errorDetail);
        return error;
    }

    public void setAuthorization(AcmeAuthorization authorization) {
        this.authorization = authorization;
        this.authorizationUuid = authorization.getUuid();
    }

    // Custom Getter for Challenge URL
    private String getBaseUrl() {
        if (ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUriString().contains("/raProfile/")) {
            return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                    + AcmeConstants.ACME_URI_HEADER + "/raProfile/"
                    + authorization.getOrder().getAcmeAccount().getRaProfile().getName();
        }
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + AcmeConstants.ACME_URI_HEADER + "/"
                + authorization.getOrder().getAcmeAccount().getAcmeProfile().getName();
    }

    public String getUrl() {
        return getBaseUrl() + "/chall/" + challengeId;
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
        AcmeChallenge that = (AcmeChallenge) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}

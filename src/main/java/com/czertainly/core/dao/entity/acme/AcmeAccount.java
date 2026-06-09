package com.czertainly.core.dao.entity.acme;

import com.otilm.api.model.client.acme.AcmeAccountListResponseDto;
import com.otilm.api.model.client.acme.AcmeAccountResponseDto;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.AccountStatus;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.MetaDefinitions;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "acme_account")
public class AcmeAccount extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<Account> {

    @Column(name="account_id")
    private String accountId;

    // length should be enough for more than 4096-bit RSA keys
    @Column(name="public_key", length = 1000)
    private String publicKey;

    @Column(name="is_default_ra_profile")
    private boolean isDefaultRaProfile;

    @Column(name="is_enabled")
    private boolean isEnabled;

    @Column(name="status")
    @Enumerated(EnumType.STRING)
    private AccountStatus status;

    @Column(name="contact")
    private String contact;

    @Column(name="terms_of_service_agreed")
    private Boolean termsOfServiceAgreed;

    @JsonBackReference
    @OneToMany(mappedBy = "acmeAccount", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<AcmeOrder> orders = new HashSet<>();

    @Column(name = "valid_orders")
    private int validOrders;

    @Column(name = "failed_orders")
    private int failedOrders;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ra_profile_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid", nullable = false)
    private UUID raProfileUuid;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "acme_profile_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private AcmeProfile acmeProfile;

    @Column(name = "acme_profile_uuid", nullable = false)
    private UUID acmeProfileUuid;

    @Override
    public Account mapToDto(){
        Account account = new Account();
        account.setContact(MetaDefinitions.deserializeArrayString(contact));
        account.setStatus(status);
        account.setTermsOfServiceAgreed(termsOfServiceAgreed);
        return account;
    }

    public AcmeAccountResponseDto mapToDtoForUi(){
        AcmeAccountResponseDto account = new AcmeAccountResponseDto();
        account.setUuid(uuid.toString());
        account.setAccountId(accountId);
        account.setEnabled(isEnabled);
        account.setContact(MetaDefinitions.deserializeArrayString(contact));
        if (acmeProfile != null) {
            account.setAcmeProfileName(acmeProfile.getName());
            account.setAcmeProfileUuid(acmeProfile.getUuid().toString());
        }
        if (raProfile != null) {
            account.setRaProfile(raProfile.mapToDtoSimplified());
        }

        int successful = 0;
        int pending = 0;
        int processing = 0;
        for (AcmeOrder order : orders) {
            switch (order.getStatus()) {
                case READY -> successful++;
                case PENDING -> pending++;
                case PROCESSING -> processing++;
                default -> {
                    // ignore
                }
            }
        }

        account.setSuccessfulOrders(successful);
        account.setPendingOrders(pending);
        account.setProcessingOrders(processing);
        account.setFailedOrders(failedOrders);
        account.setValidOrders(validOrders);

        account.setStatus(status);
        account.setTermsOfServiceAgreed(termsOfServiceAgreed);
        account.setTotalOrders(orders.size());
        return account;
    }

    public AcmeAccountListResponseDto mapToDtoForUiSimple(){
        AcmeAccountListResponseDto account = new AcmeAccountListResponseDto();
        account.setUuid(uuid.toString());
        account.setAccountId(accountId);
        account.setEnabled(isEnabled);
        if(acmeProfile != null) {
            account.setAcmeProfileName(acmeProfile.getName());
            account.setAcmeProfileUuid(acmeProfile.getUuid().toString());
        }
        if(raProfile != null) {
            account.setRaProfile(raProfile.mapToDtoSimplified());
        }
        account.setStatus(status);
        account.setTotalOrders(orders.size());
        return account;
    }

    public void setDefaultRaProfile(boolean defaultRaProfile) {
        isDefaultRaProfile = defaultRaProfile;
    }

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        this.raProfileUuid = raProfile.getUuid();
    }

    public void setAcmeProfile(AcmeProfile acmeProfile) {
        this.acmeProfile = acmeProfile;
        this.acmeProfileUuid = acmeProfile.getUuid();
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    public void setRaProfileUuid(String raProfileUuid) {
        this.raProfileUuid = UUID.fromString(raProfileUuid);
    }

    public void setAcmeProfileUuid(String acmeProfileUuid) {
        this.acmeProfileUuid = UUID.fromString(acmeProfileUuid);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        AcmeAccount that = (AcmeAccount) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}

package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.acme.AcmeAccountListResponseDto;
import com.otilm.api.model.client.acme.AcmeAccountResponseDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.acme.AccountStatus;
import com.otilm.api.model.core.acme.OrderStatus;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.acme.AcmeAccount;
import com.czertainly.core.dao.entity.acme.AcmeOrder;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.repository.AcmeProfileRepository;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.acme.AcmeAccountRepository;
import com.czertainly.core.dao.repository.acme.AcmeOrderRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

class AcmeAccountServiceTest extends BaseSpringBootTest {

    private static final String RA_PROFILE_NAME = "testRaProfile1";

    @Autowired
    private com.czertainly.core.service.RaProfileService raProfileService;

    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AcmeOrderRepository acmeOrderRepository;

    @Autowired
    private AcmeAccountExternalService acmeAccountService;

    @Autowired
    private AcmeAccountInternalService acmeAccountInternalService;

    @Autowired
    private AcmeAccountRepository acmeAccountRepository;

    @Autowired
    private AcmeProfileRepository acmeProfileRepository;

    private AcmeAccount acmeAccount;

    @BeforeEach
    public void setUp() {

        CertificateContent certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        Certificate certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setSerialNumber("123456789");
        certificateRepository.save(certificate);

        Connector connector = new Connector();
        connector.setUrl("http://localhost:3665");
        connector.setVersion(ConnectorVersion.V1);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        RaProfile raProfile = new RaProfile();
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);

        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setWebsite("sample website");
        acmeProfile.setTermsOfServiceUrl("sample terms");
        acmeProfile.setValidity(30);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setDescription("sample description");
        acmeProfile.setName("sameName");
        acmeProfile.setDnsResolverPort("53");
        acmeProfile.setDnsResolverIp("localhost");
        acmeProfile.setTermsOfServiceChangeUrl("change url");
        acmeProfileRepository.save(acmeProfile);

        acmeAccount = new AcmeAccount();
        acmeAccount.setStatus(AccountStatus.VALID);
        acmeAccount.setEnabled(true);
        acmeAccount.setAccountId("D65fAtrgfAD");
        acmeAccount.setTermsOfServiceAgreed(true);
        acmeAccount.setAcmeProfile(acmeProfile);
        acmeAccount.setRaProfile(raProfile);
        acmeAccountRepository.save(acmeAccount);
    }

    @Test
    void testListAccounts() {
        List<AcmeAccountListResponseDto> accounts = acmeAccountService.listAcmeAccounts(SecurityFilter.create());
        Assertions.assertNotNull(accounts);
        Assertions.assertFalse(accounts.isEmpty());
        Assertions.assertEquals(1, accounts.size());
        Assertions.assertEquals(acmeAccount.getAccountId(), accounts.getFirst().getAccountId());
    }

    @Test
    void testGetAccountById() throws NotFoundException {
        createExpiredOrder(OrderStatus.PENDING);
        createExpiredOrder(OrderStatus.VALID);
        acmeAccount.setValidOrders(1);
        acmeAccountRepository.save(acmeAccount);
        createExpiredOrder(OrderStatus.INVALID);
        AcmeAccountResponseDto dto = acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(acmeAccount.getAccountId(), dto.getAccountId());
        Assertions.assertNotNull(acmeAccount.getUuid());
        Assertions.assertEquals(1, dto.getFailedOrders());
        Assertions.assertEquals(1, dto.getValidOrders());

    }

    private void createExpiredOrder(OrderStatus status) {
        AcmeOrder acmeOrder = new AcmeOrder();
        acmeOrder.setAcmeAccount(acmeAccount);
        acmeOrder.setAcmeAccountUuid(acmeAccount.getUuid());
        acmeOrder.setStatus(status);
        acmeOrder.setExpires(Date.from(Instant.now().minus(1, ChronoUnit.DAYS)));
        acmeOrderRepository.save(acmeOrder);
    }

    @Test
    void testGetAccountById_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testRemoveAccount() throws NotFoundException {
        acmeAccountService.revokeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid());
        Assertions.assertEquals(AccountStatus.REVOKED, acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid()).getStatus());
    }

    @Test
    void testRemoveAccount_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"))
        );
    }

    @Test
    void testEnableAccount() throws NotFoundException {
        acmeAccountService.enableAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid());
        Assertions.assertTrue(acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid()).isEnabled());
    }

    @Test
    void testEnableAccount_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeAccountService.enableAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDisableAccount() throws NotFoundException {
        acmeAccountService.disableAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid());
        Assertions.assertFalse(acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid()).isEnabled());
    }

    @Test
    void testDisableAccount_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeAccountService.disableAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() throws NotFoundException {
        acmeAccountService.bulkRevokeAccount(List.of(acmeAccount.getSecuredUuid()));
        Assertions.assertEquals(AccountStatus.REVOKED, acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid()).getStatus());
    }

    @Test
    void testBulkEnable() throws NotFoundException {
        acmeAccountService.bulkEnableAccount(List.of(acmeAccount.getSecuredUuid()));
        Assertions.assertTrue(acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid()).isEnabled());
    }

    @Test
    void testBulkDisable() throws NotFoundException {
        acmeAccountService.bulkDisableAccount(List.of(acmeAccount.getSecuredUuid()));
        Assertions.assertFalse(acmeAccountService.getAcmeAccount(acmeAccount.getAcmeProfile().getSecuredParentUuid(), acmeAccount.getSecuredUuid()).isEnabled());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = acmeAccountInternalService.getResourceObjectInternal(acmeAccount.getUuid());
        Assertions.assertEquals(acmeAccount.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(acmeAccount.getAccountId(), nameAndUuidDto.getName());

        nameAndUuidDto = acmeAccountInternalService.getResourceObjectExternal(acmeAccount.getSecuredUuid());
        Assertions.assertEquals(acmeAccount.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(acmeAccount.getAccountId(), nameAndUuidDto.getName());
    }
}

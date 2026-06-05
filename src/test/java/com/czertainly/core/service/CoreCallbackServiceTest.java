package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.czertainly.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.czertainly.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.czertainly.api.model.core.auth.AttributeResource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Credential;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.CredentialRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.service.impl.CoreCallbackServiceImpl;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@SpringBootTest
@Transactional
@Rollback
class CoreCallbackServiceTest extends BaseSpringBootTest {

    @Autowired
    private CoreCallbackService coreCallbackService;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Test
    void testCoreGetCredentials() {
        Credential credential = new Credential();
        credential.setKind("certificate");
        credential.setEnabled(true);
        credential = credentialRepository.save(credential);

        RequestAttributeCallback callback = new RequestAttributeCallback();
        callback.setPathVariable(Map.ofEntries(Map.entry(CoreCallbackServiceImpl.CREDENTIAL_KIND_PATH_VARIABLE, credential.getKind())));

        List<ObjectAttributeContentV2> credentials = coreCallbackService.coreGetCredentials(callback);
        Assertions.assertNotNull(credentials);
        Assertions.assertFalse(credentials.isEmpty());
        Assertions.assertEquals(credential.getUuid().toString(), ((NameAndUuidDto) credentials.get(0).getData()).getUuid());
    }


    @Test
    void testCoreGetCredentialsUnknown() {
        Credential credential = new Credential();
        credential.setKind("certificate");
        credential.setEnabled(true);
        credentialRepository.save(credential);

        RequestAttributeCallback callback = new RequestAttributeCallback();
        callback.setPathVariable(Map.ofEntries(Map.entry(CoreCallbackServiceImpl.CREDENTIAL_KIND_PATH_VARIABLE, "unknown")));

        Assertions.assertTrue(coreCallbackService.coreGetCredentials(callback).isEmpty());
    }

    @Test
    void testCoreGetCredentials_validationFail() {
        RequestAttributeCallback callback = new RequestAttributeCallback();
        Assertions.assertThrows(ValidationException.class, () -> coreCallbackService.coreGetCredentials(callback));
    }

    @Test
    void testCoreGetCredentials_notFound() {
        RequestAttributeCallback callback = new RequestAttributeCallback();
        callback.setPathVariable(Map.ofEntries(Map.entry(CoreCallbackServiceImpl.CREDENTIAL_KIND_PATH_VARIABLE, "")));

        Assertions.assertTrue(coreCallbackService.coreGetCredentials(callback).isEmpty());
    }

    @Test
    void testCoreGetResourcesCertificates() throws NotFoundException {
        Certificate certificate1 = new Certificate();
        certificate1.setState(CertificateState.ISSUED);
        certificate1.setCommonName("cn1");
        certificate1.setArchived(false);
        certificateRepository.save(certificate1);
        Certificate certificate2 = new Certificate();
        certificate2.setState(CertificateState.REJECTED);
        certificate2.setArchived(false);
        certificateRepository.save(certificate2);

        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        String filter = "%s.%s".formatted(FilterField.CERTIFICATE_STATE, FilterConditionOperator.EQUALS);
        requestAttributeCallback.setFilter(Map.of(filter, "issued"));
        PaginationRequestDto pagination = new PaginationRequestDto();
        pagination.setItemsPerPage(2);
        pagination.setPageNumber(1);
        requestAttributeCallback.setPagination(pagination);
        List<ResourceObjectContent> result = coreCallbackService.coreGetResources(requestAttributeCallback, AttributeResource.CERTIFICATE);
        Assertions.assertEquals(1, result.size());
        Assertions.assertEquals(certificate1.getUuid().toString(), result.getFirst().getData().getUuid());
        Assertions.assertEquals(certificate1.getCommonName() + " (Not Issued)", result.getFirst().getData().getName());

        String invalidFilter = "xxx";
        requestAttributeCallback.setFilter(Map.of(invalidFilter, CertificateState.ISSUED));
        Assertions.assertThrows(ValidationException.class, () -> coreCallbackService.coreGetResources(requestAttributeCallback, AttributeResource.CERTIFICATE));

        requestAttributeCallback.setFilter(null);
        result = coreCallbackService.coreGetResources(requestAttributeCallback, AttributeResource.CERTIFICATE);
        Assertions.assertEquals(2, result.size());

        pagination.setItemsPerPage(1);
        requestAttributeCallback.setPagination(pagination);
        result = coreCallbackService.coreGetResources(requestAttributeCallback, AttributeResource.CERTIFICATE);
        Assertions.assertEquals(1, result.size());
    }

    @Test
    void testCoreGetResourcesAuthorities() throws NotFoundException {
        AuthorityInstanceReference authorityInstanceReference1 = new AuthorityInstanceReference();
        authorityInstanceReference1.setName("n1");
        authorityInstanceReferenceRepository.save(authorityInstanceReference1);
        AuthorityInstanceReference authorityInstanceReference2 = new AuthorityInstanceReference();
        authorityInstanceReference2.setName("n2");
        authorityInstanceReferenceRepository.save(authorityInstanceReference2);

        List<ResourceObjectContent> result = coreCallbackService.coreGetResources(new RequestAttributeCallback(), AttributeResource.AUTHORITY);
        Assertions.assertEquals(2, result.size());
    }


}

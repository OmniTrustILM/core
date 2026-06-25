package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CredentialRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.service.impl.CoreCallbackServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Covers the secured {@code coreGetResources} listing path (#1623).
 * <p>
 * SECRET double-aspect coverage is a deliberate follow-up before SECRET dropdowns ship. When listed via
 * the guarded external path, two aspects populate the same {@link com.otilm.core.security.authz.SecurityFilter}:
 * the outer {@code @ExternalAuthorizationDynamic(LIST)} on {@code ResourceServiceImpl.getResourceObjects},
 * then the inner {@code @ExternalAuthorization(SECRET, LIST, parentResource=VAULT_PROFILE, parentAction=MEMBERS)}
 * on {@code SecretServiceImpl.listResourceObjects}. Code-trace of
 * {@link com.otilm.core.security.authz.ObjectFilterAspect#populateSecurityFilter} confirms the population is
 * replace-not-append — {@code setResourceFilter}/{@code setParentResourceFilter} are last-write-wins setters,
 * so the inner SECRET-scoped filter cleanly supersedes the outer one and additionally installs the
 * VAULT_PROFILE/MEMBERS parent filter; no append, merge, or state corruption occurs. A runtime SECRET test is
 * not added here because seeding a listable SECRET requires a Connector + VaultInstance + VaultProfile +
 * SecretVersion graph (all NOT NULL FKs), which would make this focused security test fragile and is owned by
 * the SECRET-dropdown work.
 */
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

    /**
     * Differential security test pinned to CERTIFICATE — the only kind whose own {@code listResourceObjects}
     * carries no {@code @ExternalAuthorization} annotation, so it is the only kind that exercises the fix.
     * Under a principal whose OPA object-access result allows only a subset of certificates, the listing
     * must return that subset only. Fails on the bypassing internal path (returns all rows), passes once
     * the call is routed through the {@code @ExternalAuthorizationDynamic(LIST)}-guarded external path.
     */
    @Test
    void coreGetResources_certificate_restrictedPrincipal_seesOnlyAuthorizedSubset() throws NotFoundException {
        Certificate certificate1 = new Certificate();
        certificate1.setState(CertificateState.ISSUED);
        certificate1.setCommonName("cn1");
        certificate1.setArchived(false);
        certificate1 = certificateRepository.save(certificate1);
        Certificate certificate2 = new Certificate();
        certificate2.setState(CertificateState.ISSUED);
        certificate2.setCommonName("cn2");
        certificate2.setArchived(false);
        certificateRepository.save(certificate2);

        restrictObjectAccess(Resource.CERTIFICATE, List.of(certificate1.getUuid().toString()));

        List<ResourceObjectContent> result = coreCallbackService.coreGetResources(new RequestAttributeCallback(), AttributeResource.CERTIFICATE);

        Assertions.assertEquals(1, result.size());
        Assertions.assertEquals(certificate1.getUuid().toString(), result.getFirst().getData().getUuid());
    }

    /**
     * Fail-closed: a principal with no allowed certificates gets an empty list, not all rows and not an error.
     */
    @Test
    void coreGetResources_certificate_noGrants_returnsEmpty() throws NotFoundException {
        Certificate certificate = new Certificate();
        certificate.setState(CertificateState.ISSUED);
        certificate.setCommonName("cn");
        certificate.setArchived(false);
        certificateRepository.save(certificate);

        restrictObjectAccess(Resource.CERTIFICATE, List.of());

        List<ResourceObjectContent> result = coreCallbackService.coreGetResources(new RequestAttributeCallback(), AttributeResource.CERTIFICATE);

        Assertions.assertTrue(result.isEmpty());
    }

    /**
     * Characterization of an already-guarded kind. CREDENTIAL's own {@code listResourceObjects} is
     * {@code @ExternalAuthorization(CREDENTIAL, LIST)}, so it is scoped on both {@code main} and after the fix.
     * Guards against a future removal of that inner annotation and documents that CREDENTIAL was never the bypass.
     */
    @Test
    void coreGetResources_credential_alreadyScopedOnMainAndAfter() throws NotFoundException {
        Credential credential1 = new Credential();
        credential1.setName("c1");
        credential1.setEnabled(true);
        credential1 = credentialRepository.save(credential1);
        Credential credential2 = new Credential();
        credential2.setName("c2");
        credential2.setEnabled(true);
        credentialRepository.save(credential2);

        restrictObjectAccess(Resource.CREDENTIAL, List.of(credential1.getUuid().toString()));

        List<ResourceObjectContent> result = coreCallbackService.coreGetResources(new RequestAttributeCallback(), AttributeResource.CREDENTIAL);

        Assertions.assertEquals(1, result.size());
        Assertions.assertEquals(credential1.getUuid().toString(), result.getFirst().getData().getUuid());
    }

    /**
     * AC3 positive multi-grant: with three ISSUED certificates and an OPA allow-list of two of them
     * (areOnlySpecificObjectsAllowed = true), the listing returns exactly those two — proving the
     * multi-UUID allow-list path returns the full authorized set, not just the first match, and that
     * authorized dropdowns still populate after routing through the guarded external path.
     */
    @Test
    void coreGetResources_certificate_multiGrant_returnsAllAuthorized() throws NotFoundException {
        Certificate certificate1 = new Certificate();
        certificate1.setState(CertificateState.ISSUED);
        certificate1.setCommonName("cn1");
        certificate1.setArchived(false);
        certificate1 = certificateRepository.save(certificate1);
        Certificate certificate2 = new Certificate();
        certificate2.setState(CertificateState.ISSUED);
        certificate2.setCommonName("cn2");
        certificate2.setArchived(false);
        certificate2 = certificateRepository.save(certificate2);
        Certificate certificate3 = new Certificate();
        certificate3.setState(CertificateState.ISSUED);
        certificate3.setCommonName("cn3");
        certificate3.setArchived(false);
        certificate3 = certificateRepository.save(certificate3);

        restrictObjectAccess(Resource.CERTIFICATE, List.of(certificate1.getUuid().toString(), certificate2.getUuid().toString()));

        List<ResourceObjectContent> result = coreCallbackService.coreGetResources(new RequestAttributeCallback(), AttributeResource.CERTIFICATE);

        Assertions.assertEquals(2, result.size());
        Set<String> returnedUuids = result.stream().map(content -> content.getData().getUuid()).collect(Collectors.toSet());
        Assertions.assertEquals(Set.of(certificate1.getUuid().toString(), certificate2.getUuid().toString()), returnedUuids);
        Assertions.assertFalse(returnedUuids.contains(certificate3.getUuid().toString()));
    }

    /**
     * Overrides the base allow-all object-access mock for a single resource so OPA reports that only the
     * given object UUIDs are accessible (areOnlySpecificObjectsAllowed = true). Mirrors the production OPA
     * response shape consumed by {@link com.otilm.core.security.authz.ObjectFilterAspect}.
     */
    private void restrictObjectAccess(Resource resource, List<String> allowedUuids) {
        OpaObjectAccessResult restricted = new OpaObjectAccessResult();
        restricted.setActionAllowedForGroupOfObjects(false);
        restricted.setAllowedObjects(allowedUuids);
        restricted.setForbiddenObjects(List.of());
        Mockito.when(opaClient.checkObjectAccess(
                Mockito.any(),
                Mockito.argThat(req -> req != null
                        && req.getProperties() != null
                        && resource.getCode().equals(req.getProperties().get("name"))),
                Mockito.any(), Mockito.any())
        ).thenReturn(restricted);
    }

}

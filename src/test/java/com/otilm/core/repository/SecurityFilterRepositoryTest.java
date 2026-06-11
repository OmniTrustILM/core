package com.otilm.core.repository;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.repository.*;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.function.TriFunction;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.UUID;

@SpringBootTest
class SecurityFilterRepositoryTest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    @Autowired
    private ResourceObjectAssociationService resourceObjectAssociationService;

    private Group group;
    private RaProfile raProfile;
    private RaProfile raProfile2;

    private Certificate certificateGroup;
    private Certificate certificateOwner;
    private Certificate certificateRaProfile1;
    private Certificate certificateRaProfile2;

    private static final String TEST_SERIAL_NUMBER = "1122334455";

    @BeforeEach
    public void setUp() throws NotFoundException {
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("1234567890");
        certificateContent = certificateContentRepository.save(certificateContent);

        group = new Group();
        group.setName("TestGroup");
        groupRepository.save(group);

        raProfile = new RaProfile();
        raProfile.setName("Test RA profile");
        raProfile = raProfileRepository.save(raProfile);

        raProfile2 = new RaProfile();
        raProfile2.setName("Test RA profile2");
        raProfile2 = raProfileRepository.save(raProfile2);

        certificateGroup = new Certificate();
        certificateGroup.setSubjectDn("CN=testCertificateGroup");
        certificateGroup.setIssuerDn("CN=testCercertificateGroupIssuer");
        certificateGroup.setSerialNumber(TEST_SERIAL_NUMBER);
        certificateGroup.setState(CertificateState.ISSUED);
        certificateGroup.setValidationStatus(CertificateValidationStatus.VALID);
        certificateGroup.setCertificateContent(certificateContent);
        certificateGroup.setCertificateContentId(certificateContent.getId());
        certificateGroup = certificateRepository.save(certificateGroup);
        resourceObjectAssociationService.addGroup(Resource.CERTIFICATE, certificateGroup.getUuid(), group.getUuid());

        certificateOwner = new Certificate();
        certificateOwner.setSubjectDn("CN=testCertificateOwner");
        certificateOwner.setIssuerDn("CN=testCercertificateOwnerIssuer");
        certificateOwner.setSerialNumber("1234567");
        certificateOwner.setState(CertificateState.ISSUED);
        certificateOwner.setValidationStatus(CertificateValidationStatus.VALID);
        certificateOwner.setCertificateContent(certificateContent);
        certificateOwner.setCertificateContentId(certificateContent.getId());
        certificateOwner = certificateRepository.save(certificateOwner);

        NameAndUuidDto userInfo = AuthHelper.getUserIdentification();
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(Resource.CERTIFICATE);
        association.setObjectUuid(certificateOwner.getUuid());
        association.setOwnerUuid(UUID.fromString(userInfo.getUuid()));
        association.setOwnerUsername(userInfo.getName());
        ownerAssociationRepository.save(association);

        certificateRaProfile1 = new Certificate();
        certificateRaProfile1.setSubjectDn("CN=testCertificateRA1");
        certificateRaProfile1.setIssuerDn("CN=testCertificateRA1Issuer");
        certificateRaProfile1.setSerialNumber(TEST_SERIAL_NUMBER);
        certificateRaProfile1.setState(CertificateState.ISSUED);
        certificateRaProfile1.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRaProfile1.setCertificateContent(certificateContent);
        certificateRaProfile1.setCertificateContentId(certificateContent.getId());
        certificateRaProfile1.setRaProfile(raProfile);
        certificateRaProfile1 = certificateRepository.save(certificateRaProfile1);

        certificateRaProfile2 = new Certificate();
        certificateRaProfile2.setSubjectDn("CN=testCertificateRA2");
        certificateRaProfile2.setIssuerDn("CN=testCertificateRAIssuer2");
        certificateRaProfile2.setSerialNumber("12345678");
        certificateRaProfile2.setState(CertificateState.ISSUED);
        certificateRaProfile2.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRaProfile2.setCertificateContent(certificateContent);
        certificateRaProfile2.setCertificateContentId(certificateContent.getId());
        certificateRaProfile2.setRaProfile(raProfile2);
        certificateRaProfile2 = certificateRepository.save(certificateRaProfile2);
    }

    @Test
    void testSecurityFilterWithCertificates() {
        // test allow all and deny one RA profile
        SecurityFilter filter = SecurityFilter.create();
        SecurityResourceFilter resourceFilter = SecurityResourceFilter.create();
        resourceFilter.setResource(Resource.CERTIFICATE);
        resourceFilter.setResourceAction(ResourceAction.LIST);
        SecurityResourceFilter parentResourceFilter = SecurityResourceFilter.create();
        parentResourceFilter.setResource(Resource.RA_PROFILE);
        parentResourceFilter.setResourceAction(ResourceAction.MEMBERS);
        parentResourceFilter.addDeniedObjects(List.of(raProfile.getUuid().toString()));
        filter.setResourceFilter(resourceFilter);
        filter.setParentResourceFilter(parentResourceFilter);
        filter.setParentRefProperty(Certificate_.raProfileUuid.getName());

        List<Certificate> certificates = certificateRepository.findUsingSecurityFilter(filter);
        List<UUID> foundUuids = certificates.stream().map(UniquelyIdentifiedAndAudited::getUuid).toList();
        Assertions.assertEquals(2, certificates.size());
        Assertions.assertFalse(foundUuids.contains(certificateRaProfile1.getUuid()));

        // test permissions for all RA profiles with additional where clause
        parentResourceFilter.getForbiddenObjects().clear();
        parentResourceFilter.setAreOnlySpecificObjectsAllowed(true);
        parentResourceFilter.addAllowedObjects(List.of(raProfile.getUuid().toString(), raProfile2.getUuid().toString()));

        final TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> cb.equal(root.get(Certificate_.serialNumber), TEST_SERIAL_NUMBER);
        certificates = certificateRepository.findUsingSecurityFilter(filter, List.of(Certificate_.raProfile.getName()), additionalWhereClause);
        Assertions.assertEquals(1, certificates.size());
        Assertions.assertEquals(certificateRaProfile1.getUuid().toString(), certificates.getFirst().getUuid().toString());

        // test permissions for single RA Profile and group membership
        parentResourceFilter.getAllowedObjects().clear();
        parentResourceFilter.addAllowedObjects(List.of(raProfile2.getUuid().toString()));
        SecurityResourceFilter groupResourceFilter = SecurityResourceFilter.create();
        groupResourceFilter.setResource(Resource.GROUP);
        groupResourceFilter.setResourceAction(ResourceAction.MEMBERS);
        groupResourceFilter.setAreOnlySpecificObjectsAllowed(true);
        groupResourceFilter.addAllowedObjects(List.of(group.getUuid().toString()));
        filter.setGroupMembersFilter(groupResourceFilter);

        certificates = certificateRepository.findUsingSecurityFilter(filter);
        foundUuids = certificates.stream().map(UniquelyIdentifiedAndAudited::getUuid).toList();
        Assertions.assertEquals(3, certificates.size());
        Assertions.assertTrue(foundUuids.contains(certificateRaProfile2.getUuid()));
        Assertions.assertTrue(foundUuids.contains(certificateGroup.getUuid()));
        Assertions.assertTrue(foundUuids.contains(certificateOwner.getUuid()));
    }

    @Test
    void testSecurityFilterWithGroups() {
        SecurityFilter filter = SecurityFilter.create();
        SecurityResourceFilter resourceFilter = SecurityResourceFilter.create();
        resourceFilter.setResource(Resource.GROUP);
        resourceFilter.setResourceAction(ResourceAction.LIST);
        filter.setResourceFilter(resourceFilter);

        List<Group> groups = groupRepository.findUsingSecurityFilter(filter);
        Assertions.assertEquals(1, groups.size());

        final TriFunction<Root<Group>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> cb.equal(root.get(Group_.name), "ABCD");
        groups = groupRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause);
        Assertions.assertEquals(0, groups.size());
    }
}

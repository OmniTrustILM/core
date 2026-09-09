package com.otilm.core.integration.repository;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.AuditLog;
import com.otilm.core.dao.entity.AuditLog_;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Certificate_;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.Group_;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.otilm.core.dao.repository.AuditLogRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecurityFilterProjectionSpec;
import com.otilm.core.dao.repository.SortSpecification;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SortOrderBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.apache.commons.lang3.function.TriFunction;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

@SpringBootTest
class SecurityFilterRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    @Autowired
    private ResourceObjectAssociationService resourceObjectAssociationService;

    private Group group;
    private Group secondGroup;
    private Group thirdGroup;
    private RaProfile raProfile;
    private RaProfile raProfile2;

    private Certificate certificateGroup;
    private Certificate certificateOwner;
    private Certificate certificateRaProfile1;
    private Certificate certificateRaProfile2;

    private static final String TEST_SERIAL_NUMBER = "1122334455";

    /** One content per certificate: the schema enforces a single certificate per content in both directions. */
    private CertificateContent newContent() {
        CertificateContent content = new CertificateContent();
        content.setContent("1234567890-" + UUID.randomUUID());
        return certificateContentRepository.save(content);
    }

    @BeforeEach
    public void setUp() throws NotFoundException {
        group = new Group();
        group.setName("TestGroup");
        groupRepository.save(group);

        secondGroup = new Group();
        secondGroup.setName("AnotherTestGroup");
        groupRepository.save(secondGroup);

        thirdGroup = new Group();
        thirdGroup.setName("MiddleTestGroup");
        groupRepository.save(thirdGroup);

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
        certificateGroup.setCertificateContentId(newContent().getId());
        certificateGroup = certificateRepository.save(certificateGroup);
        resourceObjectAssociationService.addGroup(Resource.CERTIFICATE, certificateGroup.getUuid(), group.getUuid());
        resourceObjectAssociationService
                .addGroup(Resource.CERTIFICATE, certificateGroup.getUuid(), secondGroup.getUuid());

        certificateOwner = new Certificate();
        certificateOwner.setSubjectDn("CN=testCertificateOwner");
        certificateOwner.setIssuerDn("CN=testCercertificateOwnerIssuer");
        certificateOwner.setSerialNumber("1234567");
        certificateOwner.setState(CertificateState.ISSUED);
        certificateOwner.setValidationStatus(CertificateValidationStatus.VALID);
        certificateOwner.setCertificateContentId(newContent().getId());
        certificateOwner = certificateRepository.save(certificateOwner);

        NameAndUuidDto userInfo = AuthHelper.getUserIdentification();
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(Resource.CERTIFICATE);
        association.setObjectUuid(certificateOwner.getUuid());
        association.setOwnerUuid(UUID.fromString(userInfo.getUuid()));
        association.setOwnerUsername(userInfo.getName());
        ownerAssociationRepository.save(association);
        resourceObjectAssociationService
                .addGroup(Resource.CERTIFICATE, certificateOwner.getUuid(), thirdGroup.getUuid());

        certificateRaProfile1 = new Certificate();
        certificateRaProfile1.setSubjectDn("CN=testCertificateRA1");
        certificateRaProfile1.setIssuerDn("CN=testCertificateRA1Issuer");
        certificateRaProfile1.setSerialNumber(TEST_SERIAL_NUMBER);
        certificateRaProfile1.setState(CertificateState.ISSUED);
        certificateRaProfile1.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRaProfile1.setCertificateContentId(newContent().getId());
        certificateRaProfile1.setRaProfile(raProfile);
        certificateRaProfile1 = certificateRepository.save(certificateRaProfile1);

        certificateRaProfile2 = new Certificate();
        certificateRaProfile2.setSubjectDn("CN=testCertificateRA2");
        certificateRaProfile2.setIssuerDn("CN=testCertificateRAIssuer2");
        certificateRaProfile2.setSerialNumber("12345678");
        certificateRaProfile2.setState(CertificateState.ISSUED);
        certificateRaProfile2.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRaProfile2.setCertificateContentId(newContent().getId());
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
        parentResourceFilter
                .addAllowedObjects(List.of(raProfile.getUuid().toString(), raProfile2.getUuid().toString()));

        final TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (
                root, cb, cr) -> cb.equal(root.get(Certificate_.serialNumber), TEST_SERIAL_NUMBER);
        certificates = certificateRepository
                .findUsingSecurityFilter(filter, List.of(Certificate_.raProfile.getName()), additionalWhereClause);
        Assertions.assertEquals(1, certificates.size());
        Assertions
                .assertEquals(certificateRaProfile1.getUuid().toString(), certificates.getFirst().getUuid().toString());

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
        Assertions.assertEquals(3, groups.size());

        final TriFunction<Root<Group>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb,
                cr) -> cb.equal(root.get(Group_.name), "ABCD");
        groups = groupRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause);
        Assertions.assertEquals(0, groups.size());
    }

    @Test
    void findUsingSecurityFilter_returnsProjectedValues() {
        // given
        SecurityFilter filter = SecurityFilter.create();
        String expectedSubject = certificateGroup.getSubjectDn();

        // when
        List<String> subjects = certificateRepository
                .findUsingSecurityFilter(filter, String.class,
                        (root, cb) -> new SecurityFilterProjectionSpec<>(root.get(Certificate_.subjectDn), List.of()));

        // then
        Assertions.assertTrue(subjects.contains(expectedSubject));
    }

    @Test
    void findUsingSecurityFilter_returnsGroupedProjectedValues() {
        // given
        SecurityFilter filter = SecurityFilter.create();
        String expectedSubject = certificateGroup.getSubjectDn();

        // when
        List<Object[]> groupedSubjects = certificateRepository
                .findUsingSecurityFilter(filter, Object[].class,
                        (root, cb) -> new SecurityFilterProjectionSpec<>(
                                cb.array(root.get(Certificate_.subjectDn), cb.count(root)),
                                List.of(root.get(Certificate_.subjectDn))));

        // then
        Assertions
                .assertTrue(groupedSubjects
                        .stream()
                        .anyMatch(row -> expectedSubject.equals(row[0]) && Long.valueOf(1L).equals(row[1])));
    }

    private static SortSpecification propertySort(String fieldIdentifier, SortDirection direction) {
        return new SortSpecification(FilterFieldSource.PROPERTY, fieldIdentifier, direction);
    }

    private List<UUID> uuidsOf(List<Certificate> certificates) {
        return certificates.stream().map(UniquelyIdentifiedAndAudited::getUuid).toList();
    }

    @Test
    void sortsByRootProperty() {
        SecurityFilter filter = SecurityFilter.create();

        List<Certificate> ascending = certificateRepository
                .findUsingSecurityFilter(filter, List.of(), null, null, null,
                        propertySort("SUBJECTDN", SortDirection.ASC));
        List<Certificate> descending = certificateRepository
                .findUsingSecurityFilter(filter, List.of(), null, null, null,
                        propertySort("SUBJECTDN", SortDirection.DESC));

        Assertions
                .assertEquals(
                        List
                                .of("CN=testCertificateGroup", "CN=testCertificateOwner", "CN=testCertificateRA1",
                                        "CN=testCertificateRA2"),
                        ascending.stream().map(Certificate::getSubjectDn).toList());
        Assertions
                .assertEquals(ascending.stream().map(Certificate::getSubjectDn).toList().reversed(),
                        descending.stream().map(Certificate::getSubjectDn).toList());
    }

    @Test
    void sortsByJoinedProperty() {
        SecurityFilter filter = SecurityFilter.create();

        List<UUID> ascending = uuidsOf(certificateRepository
                .findUsingSecurityFilter(filter, List.of(), null, null, null,
                        propertySort("RA_PROFILE_NAME", SortDirection.ASC)));

        Assertions.assertEquals(4, ascending.size());
        Assertions
                .assertTrue(ascending.indexOf(certificateRaProfile1.getUuid()) < ascending
                        .indexOf(certificateRaProfile2.getUuid()));
    }

    @Test
    void sortsByJoinedPropertyWithFetchedAssociations() {
        SecurityFilter filter = SecurityFilter.create();

        List<Certificate> ascending = certificateRepository
                .findUsingSecurityFilter(filter, List.of(Certificate_.groups.getName()), null, null, null,
                        propertySort("RA_PROFILE_NAME", SortDirection.ASC));

        List<UUID> foundUuids = uuidsOf(ascending);
        Assertions.assertEquals(4, foundUuids.size());
        Assertions.assertEquals(foundUuids.size(), Set.copyOf(foundUuids).size());
        Assertions
                .assertTrue(foundUuids.indexOf(certificateRaProfile1.getUuid()) < foundUuids
                        .indexOf(certificateRaProfile2.getUuid()));
    }

    @Test
    void sortsUuidsByJoinedProperty() {
        SecurityFilter filter = SecurityFilter.create();

        List<UUID> ascending = certificateRepository
                .findUuidsUsingSecurityFilter(filter, null, null, null,
                        propertySort("RA_PROFILE_NAME", SortDirection.ASC));

        Assertions.assertEquals(4, ascending.size());
        Assertions.assertEquals(ascending.size(), Set.copyOf(ascending).size());
        Assertions
                .assertTrue(ascending.indexOf(certificateRaProfile1.getUuid()) < ascending
                        .indexOf(certificateRaProfile2.getUuid()));
    }

    @Test
    void noSortKeepsTheCallerDefaultOrder() {
        SecurityFilter filter = SecurityFilter.create();

        List<Certificate> certificates = certificateRepository
                .findUsingSecurityFilter(filter, List.of(), null, null,
                        (root, cb) -> cb.desc(root.get(Certificate_.subjectDn)));

        Assertions
                .assertEquals(
                        List
                                .of("CN=testCertificateRA2", "CN=testCertificateRA1", "CN=testCertificateOwner",
                                        "CN=testCertificateGroup"),
                        certificates.stream().map(Certificate::getSubjectDn).toList());
    }

    /**
     * Every fixture certificate carries the same state, so the requested term alone leaves the order inside the page up
     * to the database and a page boundary can repeat or drop rows. The appended uuid term is what settles it.
     */
    @Test
    void tieBreakMakesPagingStable() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = propertySort("CERTIFICATE_STATE", SortDirection.ASC);

        List<UUID> paged = new ArrayList<>();
        for (int pageNumber = 0; pageNumber < 2; pageNumber++) {
            Pageable page = PageRequest.of(pageNumber, 2);
            paged
                    .addAll(uuidsOf(
                            certificateRepository.findUsingSecurityFilter(filter, List.of(), null, page, null, sort)));
        }

        Assertions.assertEquals(4, paged.size());
        Assertions.assertEquals(4, Set.copyOf(paged).size());
        Assertions
                .assertEquals(uuidsOf(
                        certificateRepository.findUsingSecurityFilter(filter, List.of(), null, null, null, sort)),
                        paged);
    }

    @Test
    void reportsWhetherASortNeedsTheRankedUuidQuery() {
        Assertions.assertFalse(SortOrderBuilder.needsRankedUuidQuery(propertySort("SUBJECTDN", SortDirection.ASC)));
        Assertions
                .assertTrue(SortOrderBuilder.needsRankedUuidQuery(propertySort("RA_PROFILE_NAME", SortDirection.ASC)));
    }

    /**
     * The audit log is keyed by a generated id and has no uuid to break ties with. Paging it must still work, ordered
     * by whatever term the caller supplies and nothing more.
     */
    @Test
    void anEntityWithoutAUuidIsPagedWithoutATieBreak() {
        List<AuditLog> logs = auditLogRepository
                .findUsingSecurityFilter(SecurityFilter.create(), List.of(), null, PageRequest.of(0, 5),
                        (root, cb) -> cb.desc(root.get(AuditLog_.id)));

        Assertions.assertTrue(logs.isEmpty());
    }

    @Test
    void rejectsUnknownSortField() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = propertySort("NOT_A_FIELD", SortDirection.ASC);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> certificateRepository.findUsingSecurityFilter(filter, List.of(), null, null, null, sort));
    }

    /**
     * PRIVATE_KEY resolves to a path and would order fine, but what the column displays is a comparison against an
     * expected value rather than the value that path holds. The catalogue reports it as not sortable, and the request
     * is refused against that same predicate rather than answered with a silently unordered page.
     */
    @Test
    void rejectsSortFieldTheCatalogueWithholdsFromSorting() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = propertySort("PRIVATE_KEY", SortDirection.ASC);

        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> certificateRepository.findUsingSecurityFilter(filter, List.of(), null, null, null, sort));
        Assertions.assertTrue(e.getMessage().contains("cannot be used to order"));
    }

    @Test
    void rejectsSortFieldOfAnotherResource() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = propertySort("GROUP_NAME", SortDirection.ASC);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> groupRepository.findUsingSecurityFilter(filter, List.of(), null, null, null, sort));
    }

    /**
     * A certificate in two groups is two rows of the join the sort walks. Windowing those rows would give the first
     * page one certificate instead of two and hand the second page the same certificate again, so the query has to cut
     * pages out of one row per certificate.
     */
    @Test
    void pagesOneRootPerRowWhenTheSortTraversesAPluralJoin() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = propertySort("GROUP_NAME", SortDirection.ASC);

        List<UUID> paged = new ArrayList<>();
        for (int pageNumber = 0; pageNumber < 2; pageNumber++) {
            Pageable page = PageRequest.of(pageNumber, 2);
            paged
                    .addAll(uuidsOf(
                            certificateRepository.findUsingSecurityFilter(filter, List.of(), null, page, null, sort)));
        }

        Assertions.assertEquals(4, paged.size());
        Assertions.assertEquals(4, Set.copyOf(paged).size());
        Assertions
                .assertEquals(uuidsOf(
                        certificateRepository.findUsingSecurityFilter(filter, List.of(), null, null, null, sort)),
                        paged);
    }

    /** The uuid overload pages the same way, and is the one the certificate listing reads. */
    @Test
    void pagesUuidsOneRootPerRowWhenTheSortTraversesAPluralJoin() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = propertySort("GROUP_NAME", SortDirection.DESC);

        List<UUID> paged = new ArrayList<>();
        for (int pageNumber = 0; pageNumber < 2; pageNumber++) {
            paged
                    .addAll(certificateRepository
                            .findUuidsUsingSecurityFilter(filter, null, PageRequest.of(pageNumber, 2), null, sort));
        }

        Assertions.assertEquals(4, paged.size());
        Assertions.assertEquals(4, Set.copyOf(paged).size());
        Assertions
                .assertEquals(certificateRepository.findUuidsUsingSecurityFilter(filter, null, null, null, sort),
                        paged);
    }

    /**
     * The certificate in two groups sorts by the group name that decides where it belongs among the others: the first
     * of its names alphabetically when ascending, the last when descending. Its two names bracket the single name of
     * the certificate it is compared against, so ordering by either one of them alone would put the pair the other way
     * round in one of the two directions.
     */
    @Test
    void aPluralJoinSortsByTheValueThatDecidesTheRootPosition() {
        SecurityFilter filter = SecurityFilter.create();

        List<UUID> ascending = certificateRepository
                .findUuidsUsingSecurityFilter(filter, null, null, null, propertySort("GROUP_NAME", SortDirection.ASC));
        List<UUID> descending = certificateRepository
                .findUuidsUsingSecurityFilter(filter, null, null, null, propertySort("GROUP_NAME", SortDirection.DESC));

        Assertions
                .assertTrue(
                        ascending.indexOf(certificateGroup.getUuid()) < ascending.indexOf(certificateOwner.getUuid()));
        Assertions
                .assertTrue(descending.indexOf(certificateGroup.getUuid()) < descending
                        .indexOf(certificateOwner.getUuid()));
    }

    /**
     * A field identifier is unique across resources, but the attribute path behind it is not: {@code Audited.created}
     * is a mapped superclass attribute that resolves against a certificate just as well as against the signing record
     * the identifier names.
     */
    @Test
    void rejectsSortFieldInheritedFromAMappedSuperclassOfAnotherResource() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = propertySort("SIGNING_RECORD_CREATED", SortDirection.ASC);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> certificateRepository.findUsingSecurityFilter(filter, List.of(), null, null, null, sort));
    }

    /**
     * A row a column has nothing to show for must never lead the page, in either direction. PostgreSQL's own default
     * would put nulls first descending, so the direct sort path pins them last explicitly - the same placement the
     * grouped path applies, so a nullable column does not place its blanks differently depending on which path the
     * ordering happened to take.
     */
    @Test
    void aRowWithoutAValueSortsLastInBothDirectionsOnTheDirectPath() {
        certificateGroup.setCommonName("alpha");
        certificateOwner.setCommonName("bravo");
        certificateRaProfile1.setCommonName("charlie");
        certificateRepository.saveAllAndFlush(List.of(certificateGroup, certificateOwner, certificateRaProfile1));

        SecurityFilter filter = SecurityFilter.create();
        List<UUID> ascending = uuidsOf(certificateRepository
                .findUsingSecurityFilter(filter, List.of(), null, null, null,
                        propertySort("COMMON_NAME", SortDirection.ASC)));
        List<UUID> descending = uuidsOf(certificateRepository
                .findUsingSecurityFilter(filter, List.of(), null, null, null,
                        propertySort("COMMON_NAME", SortDirection.DESC)));

        Assertions.assertEquals(certificateRaProfile2.getUuid(), ascending.getLast());
        Assertions.assertEquals(certificateRaProfile2.getUuid(), descending.getLast());
    }

    /** The same placement through the grouped path, so the two cannot drift apart. */
    @Test
    void aRowWithoutAValueSortsLastInBothDirectionsOnTheGroupedPath() {
        SecurityFilter filter = SecurityFilter.create();

        List<UUID> ascending = certificateRepository
                .findUuidsUsingSecurityFilter(filter, null, null, null,
                        propertySort("RA_PROFILE_NAME", SortDirection.ASC));
        List<UUID> descending = certificateRepository
                .findUuidsUsingSecurityFilter(filter, null, null, null,
                        propertySort("RA_PROFILE_NAME", SortDirection.DESC));

        // The two certificates with no RA profile at all are the tail of both pages, whichever way the page is
        // ordered; which of the two leads that tail is the uuid tie-break's business, not this case's.
        Set<UUID> withoutRaProfile = Set.of(certificateGroup.getUuid(), certificateOwner.getUuid());
        Assertions.assertEquals(withoutRaProfile, Set.copyOf(ascending.subList(2, 4)));
        Assertions.assertEquals(withoutRaProfile, Set.copyOf(descending.subList(2, 4)));
    }

    @Test
    void rejectsSortOnAttributeSourcedField() {
        SecurityFilter filter = SecurityFilter.create();
        SortSpecification sort = new SortSpecification(FilterFieldSource.CUSTOM, "anything", SortDirection.ASC);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> certificateRepository.findUsingSecurityFilter(filter, List.of(), null, null, null, sort));
    }
}

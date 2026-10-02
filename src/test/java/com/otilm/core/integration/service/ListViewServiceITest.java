package com.otilm.core.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeUpdateRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewFieldStatus;
import com.otilm.api.model.core.listview.ListViewFilterDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.listview.ListViewSortRequestDto;
import com.otilm.api.model.core.listview.ListViewUpdateRequestDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.ListView;
import com.otilm.core.dao.repository.ListViewRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.ListViewExternalService;
import com.otilm.core.service.ListViewInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

class ListViewServiceITest extends BaseSpringBootTest {

    private static final String TEAM = "team|STRING";

    @Autowired
    private ListViewExternalService listViewService;

    @Autowired
    private ListViewInternalService listViewInternalService;

    @Autowired
    private ListViewRepository listViewRepository;

    @Autowired
    private AttributeExternalService attributeService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Autowired
    private ClusterOperationSynchronizer clusterSynchronizer;

    private UUID user;
    private UUID otherUser;

    /**
     * The single-default rule is a partial unique index, a shape no entity annotation expresses, so the
     * entity-generated test schema does not carry it. Every default in this class therefore runs against the index the
     * migration creates rather than against a schema that would accept two defaults quietly.
     */
    @BeforeEach
    void setUpUsers() {
        user = UUID.randomUUID();
        otherUser = UUID.randomUUID();
        authenticateAs(user);
        jdbcTemplate
                .execute("CREATE UNIQUE INDEX IF NOT EXISTS \"uk_list_view_single_default\" ON " + dbSchema
                        + ".\"list_view\" (\"user_uuid\", \"resource\") WHERE \"default_view\"");
    }

    @AfterEach
    void dropSingleDefaultIndex() {
        jdbcTemplate.execute("DROP INDEX IF EXISTS " + dbSchema + ".\"uk_list_view_single_default\"");
    }

    /**
     * A view has to follow the user across sessions, so nothing about it may live in the session: signing in again as
     * the same user has to find it, and signing in as anyone else must not.
     */
    private void authenticateAs(UUID userUuid) {
        UserProfileDto profile = new UserProfileDto();
        UserDto userDto = new UserDto();
        userDto.setUuid(userUuid.toString());
        userDto.setUsername("user-" + userUuid);
        profile.setUser(userDto);

        String rawData;
        try {
            rawData = new ObjectMapper().writeValueAsString(profile);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }

        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, userDto.getUuid(),
                userDto.getUsername(), List.of(), rawData);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }

    private static ListViewColumnDto column(String fieldIdentifier) {
        return new ListViewColumnDto(FilterFieldSource.PROPERTY, fieldIdentifier, null);
    }

    private static ListViewColumnDto column(String fieldIdentifier, String label) {
        return new ListViewColumnDto(FilterFieldSource.PROPERTY, fieldIdentifier, label);
    }

    private static ListViewRequestDto request(String name, ListViewColumnDto... columns) {
        ListViewRequestDto request = new ListViewRequestDto();
        request.setResource(Resource.CERTIFICATE);
        request.setName(name);
        request.setColumns(List.of(columns));
        return request;
    }

    private static ListViewUpdateRequestDto update(String name, ListViewColumnDto... columns) {
        ListViewUpdateRequestDto request = new ListViewUpdateRequestDto();
        request.setName(name);
        request.setColumns(List.of(columns));
        return request;
    }

    private static List<String> identifiersOf(ListViewDto view) {
        return view.getColumns().stream().map(ListViewColumnDto::getFieldIdentifier).toList();
    }

    private static List<String> termsOf(List<ListViewFilterDto> filters) {
        return filters
                .stream()
                .map(filter -> "%s %s %s %s"
                        .formatted(filter.getFieldSource(), filter.getFieldIdentifier(), filter.getCondition(),
                                filter.getValue()))
                .toList();
    }

    private static ListViewRequestDto keyRequest(String name) {
        ListViewRequestDto request = request(name, column("CKI_NAME"));
        request.setResource(Resource.CRYPTOGRAPHIC_KEY);
        return request;
    }

    private List<String> namesOf(Resource resource) {
        return listViewService.listViews(resource).stream().map(ListViewDto::getName).toList();
    }

    @Test
    void aViewSurvivesTheSessionAndIsInvisibleToOtherUsers() throws AlreadyExistException {
        ListViewDto created = listViewService.createView(request("Expiry watch", column("COMMON_NAME")));

        authenticateAs(user);
        Assertions
                .assertEquals(List.of(created.getUuid()),
                        listViewService.listViews(Resource.CERTIFICATE).stream().map(ListViewDto::getUuid).toList());

        authenticateAs(otherUser);
        Assertions.assertTrue(listViewService.listViews(Resource.CERTIFICATE).isEmpty());
        Assertions.assertTrue(listViewService.listViews(null).isEmpty());
    }

    @Test
    void viewsAreListedInTheOrderTheyWereCreated() throws AlreadyExistException {
        listViewService.createView(request("B", column("COMMON_NAME")));
        listViewService.createView(keyRequest("Z"));
        listViewService.createView(request("A", column("COMMON_NAME")));
        listViewService.createView(keyRequest("Y"));
        listViewService.createView(request("C", column("COMMON_NAME")));

        Assertions.assertEquals(List.of("B", "Z", "A", "Y", "C"), namesOf(null));
        Assertions.assertEquals(List.of("B", "A", "C"), namesOf(Resource.CERTIFICATE));
        Assertions.assertEquals(List.of("Z", "Y"), namesOf(Resource.CRYPTOGRAPHIC_KEY));
    }

    @Test
    void aViewOfAnotherUserIsNotAddressable() throws AlreadyExistException {
        ListViewDto created = listViewService.createView(request("Expiry watch", column("COMMON_NAME")));

        authenticateAs(otherUser);
        Assertions.assertThrows(NotFoundException.class, () -> listViewService.deleteView(created.getUuid()));
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> listViewService.editView(created.getUuid(), update("Renamed", column("COMMON_NAME"))));
    }

    @Test
    void viewsAreListedCreatedRenamedEditedAndDeleted() throws AlreadyExistException, NotFoundException {
        ListViewDto created = listViewService
                .createView(request("Expiry watch", column("COMMON_NAME"), column("NOT_AFTER")));

        ListViewDto renamed = listViewService.editView(created.getUuid(), update("Expiring soon", column("NOT_AFTER")));
        Assertions.assertEquals("Expiring soon", renamed.getName());
        Assertions.assertEquals(List.of("NOT_AFTER"), identifiersOf(renamed));
        Assertions.assertEquals(created.getUuid(), renamed.getUuid());

        listViewService.deleteView(created.getUuid());
        Assertions.assertTrue(listViewService.listViews(Resource.CERTIFICATE).isEmpty());
    }

    @Test
    void aSecondViewOfTheSameNameIsRejected() throws AlreadyExistException {
        listViewService.createView(request("Expiry watch", column("COMMON_NAME")));

        ListViewRequestDto duplicate = request("Expiry watch", column("NOT_AFTER"));
        Assertions.assertThrows(AlreadyExistException.class, () -> listViewService.createView(duplicate));
    }

    @Test
    void theSameNameIsFreeForAnotherUserAndForAnotherResource() throws AlreadyExistException {
        listViewService.createView(request("Expiry watch", column("COMMON_NAME")));

        ListViewRequestDto otherResource = request("Expiry watch", column("CKI_NAME"));
        otherResource.setResource(Resource.CRYPTOGRAPHIC_KEY);
        Assertions.assertNotNull(listViewService.createView(otherResource));

        authenticateAs(otherUser);
        Assertions.assertNotNull(listViewService.createView(request("Expiry watch", column("COMMON_NAME"))));
    }

    @Test
    void renamingOntoTheNameOfAnotherViewIsRejected() throws AlreadyExistException {
        listViewService.createView(request("Expiry watch", column("COMMON_NAME")));
        ListViewDto second = listViewService.createView(request("Everything", column("COMMON_NAME")));

        ListViewUpdateRequestDto clash = update("Expiry watch", column("COMMON_NAME"));
        Assertions.assertThrows(AlreadyExistException.class, () -> listViewService.editView(second.getUuid(), clash));
    }

    @Test
    void aViewKeepsItsOwnNameWhenSavedUnchanged() throws AlreadyExistException, NotFoundException {
        ListViewDto created = listViewService.createView(request("Expiry watch", column("COMMON_NAME")));

        ListViewDto saved = listViewService
                .editView(created.getUuid(), update("Expiry watch", column("COMMON_NAME"), column("NOT_AFTER")));

        Assertions.assertEquals(List.of("COMMON_NAME", "NOT_AFTER"), identifiersOf(saved));
    }

    @Test
    void columnOrderRoundTripsExactlyAsSent() throws AlreadyExistException {
        List<String> order = List.of("NOT_AFTER", "COMMON_NAME", "CERTIFICATE_STATE");

        ListViewDto created = listViewService
                .createView(
                        request("Ordered", column("NOT_AFTER"), column("COMMON_NAME"), column("CERTIFICATE_STATE")));

        Assertions.assertEquals(order, identifiersOf(created));
        Assertions.assertEquals(order, identifiersOf(listViewService.listViews(Resource.CERTIFICATE).getFirst()));
    }

    @Test
    void aLabelOverrideRoundTripsAndCanBeClearedBackToTheCatalogueLabel()
            throws AlreadyExistException, NotFoundException {
        ListViewDto created = listViewService
                .createView(request("Labelled", column("COMMON_NAME", "Subject"), column("NOT_AFTER")));

        Assertions.assertEquals("Subject", created.getColumns().getFirst().getLabel());
        // absent rather than filled in from the catalogue, so a caller can tell an override from the default
        Assertions.assertNull(created.getColumns().get(1).getLabel());

        ListViewDto cleared = listViewService
                .editView(created.getUuid(), update("Labelled", column("COMMON_NAME"), column("NOT_AFTER")));
        Assertions.assertNull(cleared.getColumns().getFirst().getLabel());
    }

    @Test
    void filtersAndOrderingAreStoredAndReturnedWithTheColumns() throws AlreadyExistException {
        ListViewFilterDto filter = new ListViewFilterDto(FilterFieldSource.PROPERTY, "COMMON_NAME",
                FilterConditionOperator.CONTAINS, "test");
        SearchSortRequestDto sort = new SearchSortRequestDto(FilterFieldSource.PROPERTY, "NOT_AFTER",
                SortDirection.DESC);

        ListViewRequestDto request = request("Sliced", column("COMMON_NAME"));
        request.setFilters(List.of(filter));
        request.setSort(sent(sort));

        listViewService.createView(request);

        ListViewDto stored = listViewService.listViews(Resource.CERTIFICATE).getFirst();
        Assertions.assertEquals(List.of("COMMON_NAME"), identifiersOf(stored));
        Assertions.assertEquals(1, stored.getFilters().size());
        Assertions.assertEquals("COMMON_NAME", stored.getFilters().getFirst().getFieldIdentifier());
        Assertions.assertEquals(FilterConditionOperator.CONTAINS, stored.getFilters().getFirst().getCondition());
        Assertions.assertEquals(sort, stored.getSort());
    }

    @Test
    void aCryptoAssetViewKeepsItsColumnsAndOrdering() throws AlreadyExistException {
        SearchSortRequestDto sort = new SearchSortRequestDto(FilterFieldSource.PROPERTY, "CBOM_ASSET_NAME",
                SortDirection.DESC);
        ListViewRequestDto request = request("Inventory", column("CBOM_ASSET_NAME"),
                column("CBOM_ASSET_PQC_VERDICT", "Readiness"), column("CBOM_ASSET_SOURCE_COUNT"));
        request.setResource(Resource.CRYPTO_ASSET);
        request.setSort(sent(sort));

        listViewService.createView(request);

        ListViewDto stored = listViewService.listViews(Resource.CRYPTO_ASSET).getFirst();
        Assertions
                .assertEquals(List.of("CBOM_ASSET_NAME", "CBOM_ASSET_PQC_VERDICT", "CBOM_ASSET_SOURCE_COUNT"),
                        identifiersOf(stored));
        Assertions.assertEquals("Readiness", stored.getColumns().get(1).getLabel());
        Assertions.assertEquals(sort, stored.getSort());
    }

    @Test
    void aCryptoAssetColumnTheListingCannotShowIsRejectedOnWrite() {
        ListViewRequestDto request = request("Blank", column("CBOM_ASSET_NAME"), column("CBOM_ASSET_OID"));
        request.setResource(Resource.CRYPTO_ASSET);

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CBOM_ASSET_OID"));
    }

    @Test
    void aViewWithoutFiltersOrOrderingReportsNeither() throws AlreadyExistException {
        ListViewDto created = listViewService.createView(request("Plain", column("COMMON_NAME")));

        Assertions.assertNull(created.getFilters());
        Assertions.assertNull(created.getSort());
    }

    @Test
    void markingAViewDefaultClearsThePreviousDefault() throws AlreadyExistException, NotFoundException {
        ListViewRequestDto first = request("First", column("COMMON_NAME"));
        first.setDefaultView(true);
        ListViewDto firstView = listViewService.createView(first);

        ListViewRequestDto second = request("Second", column("NOT_AFTER"));
        second.setDefaultView(true);
        ListViewDto secondView = listViewService.createView(second);

        Assertions.assertEquals(List.of(secondView.getUuid()), defaultViewUuids());

        ListViewUpdateRequestDto promoteFirst = update("First", column("COMMON_NAME"));
        promoteFirst.setDefaultView(true);
        listViewService.editView(firstView.getUuid(), promoteFirst);

        Assertions.assertEquals(List.of(firstView.getUuid()), defaultViewUuids());
    }

    @Test
    void theDefaultOfOneResourceDoesNotClearTheDefaultOfAnother() throws AlreadyExistException {
        ListViewRequestDto certificates = request("Certificates", column("COMMON_NAME"));
        certificates.setDefaultView(true);
        ListViewDto certificateView = listViewService.createView(certificates);

        ListViewRequestDto keys = request("Keys", column("CKI_NAME"));
        keys.setResource(Resource.CRYPTOGRAPHIC_KEY);
        keys.setDefaultView(true);
        ListViewDto keyView = listViewService.createView(keys);

        Assertions
                .assertEquals(List.of(certificateView.getUuid(), keyView.getUuid()).stream().sorted().toList(),
                        defaultViewUuids().stream().sorted().toList());
    }

    private List<String> defaultViewUuids() {
        return listViewRepository
                .findByUserUuidOrderByCreatedAscUuidAsc(user)
                .stream()
                .filter(ListView::isDefaultView)
                .map(view -> view.getUuid().toString())
                .toList();
    }

    /**
     * A field can leave the catalogue after a view has stored it - a custom attribute is deleted, a property is
     * retired. Reading the view still returns the column in place, so the client can name it as unavailable, and a
     * full-row write the client sends back does not erase it before the user has seen it.
     */
    @Test
    void aColumnWhoseFieldNoLongerExistsIsKeptOnRead() {
        store("Stale",
                List
                        .of(column("COMMON_NAME"), column("RETIRED_FIELD"),
                                new ListViewColumnDto(FilterFieldSource.CUSTOM, "deleted|STRING", null)),
                null);

        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        Assertions.assertEquals(List.of("COMMON_NAME", "RETIRED_FIELD", "deleted|STRING"), identifiersOf(read));
    }

    /**
     * A view holding a column for a deleted attribute has to stay editable: renaming or pinning it sends the whole row
     * back, that column included, and refusing the request over it would freeze the view.
     */
    @Test
    void aColumnWhoseFieldNoLongerExistsSurvivesARename() throws NotFoundException, AlreadyExistException {
        ListViewColumnDto deleted = new ListViewColumnDto(FilterFieldSource.CUSTOM, "deleted|STRING", null);
        store("Stale", List.of(column("COMMON_NAME"), deleted), null);
        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        ListViewDto renamed = listViewService
                .editView(read.getUuid(), update("Renamed", column("COMMON_NAME"), deleted));

        Assertions.assertEquals("Renamed", renamed.getName());
        Assertions.assertEquals(List.of("COMMON_NAME", "deleted|STRING"), identifiersOf(renamed));
    }

    @Test
    void aFilterOnAFieldThatNoLongerExistsSurvivesARename() throws NotFoundException, AlreadyExistException {
        ListViewFilterDto deleted = new ListViewFilterDto(FilterFieldSource.CUSTOM, "deleted|STRING",
                FilterConditionOperator.EQUALS, "x");
        ListView stored = storeFiltered("Filtered", List.of(column("COMMON_NAME")), List.of(deleted));

        ListViewUpdateRequestDto rename = update("Renamed", column("COMMON_NAME"));
        rename.setFilters(List.of(deleted));
        ListViewDto renamed = listViewService.editView(stored.getUuid().toString(), rename);

        Assertions.assertEquals("Renamed", renamed.getName());
        Assertions.assertEquals(termsOf(List.of(deleted)), termsOf(renamed.getFilters()));
    }

    @Test
    void aFilterOnAFieldThatNoLongerExistsCannotBeChangedOnAnExistingView() {
        ListViewFilterDto deleted = new ListViewFilterDto(FilterFieldSource.CUSTOM, "deleted|STRING",
                FilterConditionOperator.EQUALS, "x");
        ListView stored = storeFiltered("Filtered", List.of(column("COMMON_NAME")), List.of(deleted));

        ListViewUpdateRequestDto edit = update("Filtered", column("COMMON_NAME"));
        edit
                .setFilters(List
                        .of(new ListViewFilterDto(FilterFieldSource.CUSTOM, "deleted|STRING",
                                FilterConditionOperator.CONTAINS, "x")));
        String uuid = stored.getUuid().toString();

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.editView(uuid, edit));
        Assertions.assertTrue(e.getMessage().contains("has no field deleted|STRING"));
    }

    @Test
    void aStoredFilterOnAFieldThatNoLongerExistsCannotBeRepeated() {
        ListViewFilterDto deleted = new ListViewFilterDto(FilterFieldSource.CUSTOM, "deleted|STRING",
                FilterConditionOperator.EQUALS, "x");
        ListView stored = storeFiltered("Filtered", List.of(column("COMMON_NAME")), List.of(deleted));

        ListViewUpdateRequestDto edit = update("Filtered", column("COMMON_NAME"));
        edit.setFilters(List.of(deleted, deleted));
        String uuid = stored.getUuid().toString();

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.editView(uuid, edit));
        Assertions.assertTrue(e.getMessage().contains("has no field deleted|STRING"));
    }

    @Test
    void aFilterOnAFieldThatNoLongerExistsCannotBeAddedToAnExistingView() throws AlreadyExistException {
        ListViewDto created = listViewService.createView(request("Clean", column("COMMON_NAME")));
        ListViewUpdateRequestDto edit = update("Clean", column("COMMON_NAME"));
        edit
                .setFilters(List
                        .of(new ListViewFilterDto(FilterFieldSource.CUSTOM, "deleted|STRING",
                                FilterConditionOperator.EQUALS, "x")));
        String uuid = created.getUuid();

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.editView(uuid, edit));
        Assertions.assertTrue(e.getMessage().contains("has no field deleted|STRING"));
    }

    @Test
    void aColumnWhoseFieldNoLongerExistsCannotBeAddedToAnExistingView() throws AlreadyExistException {
        ListViewDto created = listViewService.createView(request("Clean", column("COMMON_NAME")));
        ListViewColumnDto deleted = new ListViewColumnDto(FilterFieldSource.CUSTOM, "deleted|STRING", null);
        String uuid = created.getUuid();
        ListViewUpdateRequestDto edit = update("Clean", column("COMMON_NAME"), deleted);

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.editView(uuid, edit));
        Assertions.assertTrue(e.getMessage().contains("has no field deleted|STRING"));
    }

    @Test
    void aColumnWhoseFieldNoLongerExistsIsRejectedOnCreate() {
        ListViewRequestDto request = request("Copy", column("COMMON_NAME"),
                new ListViewColumnDto(FilterFieldSource.CUSTOM, "deleted|STRING", null));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("has no field deleted|STRING"));
    }

    /**
     * Hiding a custom attribute keeps it in the catalogue but narrows it to presence conditions, so a view already
     * filtering on one of its values would otherwise be refused on every rename.
     */
    @Test
    void aFilterWhoseConditionTheFieldNoLongerOffersSurvivesARename()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewFilterDto pki = teamFilter(FilterConditionOperator.EQUALS, "pki");
        ListViewRequestDto request = request("Team", column("COMMON_NAME"));
        request.setFilters(List.of(pki));
        ListViewDto created = listViewService.createView(request);
        hide(team);

        ListViewUpdateRequestDto rename = update("Renamed", column("COMMON_NAME"));
        rename.setFilters(List.of(pki));
        ListViewDto renamed = listViewService.editView(created.getUuid(), rename);

        Assertions.assertEquals("Renamed", renamed.getName());
        Assertions.assertEquals(termsOf(List.of(pki)), termsOf(renamed.getFilters()));
        Assertions.assertEquals(ListViewFieldStatus.UNAVAILABLE, renamed.getFilters().getFirst().getStatus());
    }

    @Test
    void aChangedFilterOnAFieldThatNoLongerOffersItsConditionIsRejected()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewRequestDto request = request("Team", column("COMMON_NAME"));
        request.setFilters(List.of(teamFilter(FilterConditionOperator.EQUALS, "pki")));
        ListViewDto created = listViewService.createView(request);
        hide(team);

        ListViewUpdateRequestDto edit = update("Team", column("COMMON_NAME"));
        edit.setFilters(List.of(teamFilter(FilterConditionOperator.EQUALS, "ops")));
        String uuid = created.getUuid();

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.editView(uuid, edit));
        Assertions.assertTrue(e.getMessage().contains("does not offer these filter conditions: team|STRING EQUALS"));
    }

    private UUID createTeamAttribute() throws AlreadyExistException, AttributeException {
        CustomAttributeCreateRequestDto request = new CustomAttributeCreateRequestDto();
        request.setName("team");
        request.setLabel("Team");
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setContentType(AttributeContentType.STRING);
        request.setVisible(true);
        return UUID.fromString(attributeService.createCustomAttribute(request).getUuid());
    }

    private void hide(UUID attribute) throws NotFoundException, AttributeException {
        CustomAttributeUpdateRequestDto request = new CustomAttributeUpdateRequestDto();
        request.setLabel("Team");
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setVisible(false);
        attributeService.editCustomAttribute(attribute, request);
    }

    private static ListViewFilterDto teamFilter(FilterConditionOperator condition, String value) {
        return new ListViewFilterDto(FilterFieldSource.CUSTOM, "team|STRING", condition, value);
    }

    /**
     * A field can stop being a column after a view has stored it, which is what happens to every view saved before the
     * listing's own columns were read against its mapper. The column is still returned: the client reads the same
     * catalogue and can name it as unavailable and offer to take it out, which withholding it silently prevents.
     */
    @Test
    void aColumnTheListingNoLongerShowsIsKeptOnRead() {
        store("Withdrawn", List.of(column("COMMON_NAME"), column("CERTIFICATE_PROTOCOL")), null);

        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        Assertions.assertEquals(List.of("COMMON_NAME", "CERTIFICATE_PROTOCOL"), identifiersOf(read));
        Assertions
                .assertEquals(List.of(ListViewFieldStatus.AVAILABLE, ListViewFieldStatus.UNAVAILABLE),
                        read.getColumns().stream().map(ListViewColumnDto::getStatus).toList());
    }

    /**
     * A view whose every column was withdrawn at once. Filtering them out would answer an empty column list, which no
     * update request may carry, so the next rename of such a view would be refused for a reason the caller cannot act
     * on.
     */
    @Test
    void aViewWhoseEveryColumnWasWithdrawnStillReadsBackASaveableShape()
            throws NotFoundException, AlreadyExistException {
        store("All withdrawn", List.of(column("CERTIFICATE_PROTOCOL"), column("KEY_USAGE")), null);

        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        Assertions.assertEquals(List.of("CERTIFICATE_PROTOCOL", "KEY_USAGE"), identifiersOf(read));
        ListViewDto renamed = listViewService
                .editView(read.getUuid(), update("Renamed", column("CERTIFICATE_PROTOCOL"), column("KEY_USAGE")));
        Assertions.assertEquals("Renamed", renamed.getName());
    }

    /**
     * The same for a stored ordering, which the listing now refuses: returning it would make the view unusable rather
     * than merely unordered.
     */
    @Test
    void anOrderingTheListingNoLongerAppliesIsDroppedOnRead() {
        store("Stale ordering", List.of(column("COMMON_NAME")),
                new SearchSortRequestDto(FilterFieldSource.PROPERTY, "CERTIFICATE_PROTOCOL", SortDirection.ASC));

        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        Assertions.assertNull(read.getSort());
        Assertions.assertEquals(List.of("COMMON_NAME"), identifiersOf(read));
    }

    private void store(String name, List<ListViewColumnDto> columns, SearchSortRequestDto sort) {
        save(name, columns, null, sort);
    }

    private ListView storeFiltered(String name, List<ListViewColumnDto> columns, List<ListViewFilterDto> filters) {
        return save(name, columns, filters, null);
    }

    private ListView save(String name, List<ListViewColumnDto> columns, List<ListViewFilterDto> filters,
            SearchSortRequestDto sort) {
        ListView stored = new ListView();
        stored.setUserUuid(user);
        stored.setResource(Resource.CERTIFICATE);
        stored.setName(name);
        stored.setColumns(columns);
        stored.setFilters(filters);
        stored.setSort(sort);
        return listViewRepository.save(stored);
    }

    /** A view that names the team attribute everywhere a view can: a column, a filter and the ordering. */
    private ListView saveTeamView(String name) {
        return save(name, List.of(column("COMMON_NAME"), new ListViewColumnDto(FilterFieldSource.CUSTOM, TEAM, null)),
                List.of(teamFilter(FilterConditionOperator.EQUALS, "blue")),
                new SearchSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.ASC));
    }

    /**
     * A view saved while its owner could read an attribute, read once they may not. The attribute has left their
     * catalogue, so the view reads back as it does once a field is deleted: the column and the filter are kept for the
     * client to mark unavailable, and the ordering the listing would now refuse is dropped.
     */
    @Test
    void aViewOnAnAttributeTheOwnerMayNoLongerReadKeepsItButNotItsOrdering()
            throws AlreadyExistException, AttributeException {
        UUID team = createTeamAttribute();
        saveTeamView("Team");
        forbidObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(team));

        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        Assertions.assertEquals(List.of("COMMON_NAME", TEAM), identifiersOf(read));
        Assertions
                .assertEquals(termsOf(List.of(teamFilter(FilterConditionOperator.EQUALS, "blue"))),
                        termsOf(read.getFilters()));
        Assertions.assertNull(read.getSort());
    }

    /** What the client does with a view it read: sends it back with a new name, and the save has to succeed. */
    @Test
    void aViewOnAnAttributeTheOwnerMayNoLongerReadCanStillBeRenamed()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        saveTeamView("Team");
        forbidObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(team));
        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        ListViewUpdateRequestDto rename = update("Team renamed", read.getColumns().toArray(ListViewColumnDto[]::new));
        rename.setFilters(read.getFilters());
        rename.setSort(sent(read.getSort()));
        ListViewDto renamed = listViewService.editView(read.getUuid(), rename);

        Assertions.assertEquals("Team renamed", renamed.getName());
        Assertions.assertEquals(List.of("COMMON_NAME", TEAM), identifiersOf(renamed));
    }

    /** Refused as a field that does not exist would be, so the answer does not confirm the definition either. */
    @Test
    void aViewCannotNameAnAttributeTheCallerMayNotRead() throws AlreadyExistException, AttributeException {
        UUID team = createTeamAttribute();
        forbidObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(team));
        ListViewRequestDto request = request("Team", column("COMMON_NAME"),
                new ListViewColumnDto(FilterFieldSource.CUSTOM, TEAM, null));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("has no field " + TEAM), e.getMessage());
    }

    private static ListViewColumnDto teamColumn() {
        return new ListViewColumnDto(FilterFieldSource.CUSTOM, TEAM, null);
    }

    private static ListViewColumnDto teamColumnOf(ListViewDto view) {
        return view.getColumns().stream().filter(c -> TEAM.equals(c.getFieldIdentifier())).findFirst().orElseThrow();
    }

    private ListViewDto readTheOnlyView() {
        return listViewService.listViews(Resource.CERTIFICATE).getFirst();
    }

    private ListViewDto createTeamColumnView() throws AlreadyExistException {
        return listViewService.createView(request("Team", column("COMMON_NAME"), teamColumn()));
    }

    private ListViewDto createTeamFilterView() throws AlreadyExistException {
        ListViewRequestDto request = request("Team", column("COMMON_NAME"));
        request.setFilters(List.of(teamFilter(FilterConditionOperator.EQUALS, "pki")));
        return listViewService.createView(request);
    }

    private UUID recreateTeamAttribute(UUID team) throws NotFoundException, AlreadyExistException, AttributeException {
        attributeService.deleteCustomAttribute(team);
        return createTeamAttribute();
    }

    private static ListViewSortRequestDto sent(SearchSortRequestDto sort) {
        return sort == null
                ? null
                : new ListViewSortRequestDto(sort.getFieldSource(), sort.getFieldIdentifier(), sort.getDirection());
    }

    private static ListViewUpdateRequestDto savedBack(ListViewDto read, String name) {
        ListViewUpdateRequestDto request = update(name, read.getColumns().toArray(ListViewColumnDto[]::new));
        request.setFilters(read.getFilters());
        request.setSort(sent(read.getSort()));
        return request;
    }

    @Test
    void anAttributeColumnIsBoundToTheDefinitionItWasAddedFor() throws AlreadyExistException, AttributeException {
        UUID team = createTeamAttribute();

        ListViewDto created = createTeamColumnView();

        Assertions.assertEquals(List.of(team), teamColumnOf(created).getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, teamColumnOf(created).getStatus());
        Assertions.assertEquals(List.of(team), teamColumnOf(readTheOnlyView()).getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, teamColumnOf(readTheOnlyView()).getStatus());
    }

    @Test
    void aPropertyColumnCarriesNoBindingAndReadsAvailable() throws AlreadyExistException {
        listViewService.createView(request("Plain", column("COMMON_NAME")));

        ListViewColumnDto read = readTheOnlyView().getColumns().getFirst();

        Assertions.assertNull(read.getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, read.getStatus());
    }

    @Test
    void aColumnOfADeletedAttributeReadsUnavailable()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        createTeamColumnView();

        attributeService.deleteCustomAttribute(team);

        Assertions.assertEquals(ListViewFieldStatus.UNAVAILABLE, teamColumnOf(readTheOnlyView()).getStatus());
    }

    @Test
    void anAttributeRecreatedUnderTheSameNameAndTypeDoesNotClaimAStoredColumn()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        createTeamColumnView();

        recreateTeamAttribute(team);

        ListViewColumnDto read = teamColumnOf(readTheOnlyView());
        Assertions.assertEquals(ListViewFieldStatus.REPLACED, read.getStatus());
        Assertions.assertEquals(List.of(team), read.getAttributeDefinitionUuids());
    }

    @Test
    void anAttributeRecreatedUnderTheSameNameAndTypeDoesNotClaimAStoredFilter()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewDto created = createTeamFilterView();
        Assertions.assertEquals(List.of(team), created.getFilters().getFirst().getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, created.getFilters().getFirst().getStatus());

        attributeService.deleteCustomAttribute(team);
        Assertions.assertEquals(ListViewFieldStatus.UNAVAILABLE, readTheOnlyView().getFilters().getFirst().getStatus());
        createTeamAttribute();

        ListViewFilterDto read = readTheOnlyView().getFilters().getFirst();
        Assertions.assertEquals(ListViewFieldStatus.REPLACED, read.getStatus());
        Assertions.assertEquals(List.of(team), read.getAttributeDefinitionUuids());
    }

    /** What a client that predates the binding does: it sends back what it read, under a new name. */
    @Test
    void aReplacedColumnAndFilterStayReplacedWhenTheViewIsSavedBack()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewRequestDto request = request("Team", column("COMMON_NAME"), teamColumn());
        request.setFilters(List.of(teamFilter(FilterConditionOperator.EQUALS, "pki")));
        listViewService.createView(request);
        recreateTeamAttribute(team);
        ListViewDto read = readTheOnlyView();

        ListViewDto renamed = listViewService.editView(read.getUuid(), savedBack(read, "Renamed"));

        Assertions.assertEquals(ListViewFieldStatus.REPLACED, teamColumnOf(renamed).getStatus());
        Assertions.assertEquals(List.of(team), teamColumnOf(renamed).getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.REPLACED, renamed.getFilters().getFirst().getStatus());
        Assertions.assertEquals(ListViewFieldStatus.REPLACED, teamColumnOf(readTheOnlyView()).getStatus());
        Assertions.assertEquals(ListViewFieldStatus.REPLACED, readTheOnlyView().getFilters().getFirst().getStatus());
    }

    @Test
    void aReplacedColumnSentWithoutItsBindingStaysReplaced()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewDto created = createTeamColumnView();
        recreateTeamAttribute(team);

        ListViewDto renamed = listViewService
                .editView(created.getUuid(), update("Renamed", column("COMMON_NAME"), teamColumn()));

        Assertions.assertEquals(ListViewFieldStatus.REPLACED, teamColumnOf(renamed).getStatus());
    }

    @Test
    void rebindingAReplacedColumnBindsItToTheCurrentDefinition()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        createTeamColumnView();
        UUID recreated = recreateTeamAttribute(team);
        ListViewDto read = readTheOnlyView();
        teamColumnOf(read).setRebind(true);

        ListViewDto rebound = listViewService.editView(read.getUuid(), savedBack(read, "Team"));

        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, teamColumnOf(rebound).getStatus());
        Assertions.assertEquals(List.of(recreated), teamColumnOf(rebound).getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, teamColumnOf(readTheOnlyView()).getStatus());
        Assertions.assertNull(teamColumnOf(readTheOnlyView()).getRebind());
    }

    @Test
    void rebindingAReplacedFilterBindsItToTheCurrentDefinition()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        createTeamFilterView();
        UUID recreated = recreateTeamAttribute(team);
        ListViewDto read = readTheOnlyView();
        read.getFilters().getFirst().setRebind(true);

        ListViewDto rebound = listViewService.editView(read.getUuid(), savedBack(read, "Team"));

        ListViewFilterDto filter = rebound.getFilters().getFirst();
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, filter.getStatus());
        Assertions.assertEquals(List.of(recreated), filter.getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, readTheOnlyView().getFilters().getFirst().getStatus());
    }

    /**
     * The request that waited held the view as it was before the rebind, loaded in a session that stays open across the
     * write. Carrying the binding from that copy would put back the one the rebind had just replaced.
     */
    @Test
    void aSaveThatWaitedOnARebindKeepsTheRebinding()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        createTeamColumnView();
        UUID recreated = recreateTeamAttribute(team);
        ListViewUpdateRequestDto rename = savedBack(readTheOnlyView(), "Renamed");
        ListViewDto read = readTheOnlyView();
        teamColumnOf(read).setRebind(true);
        ListViewUpdateRequestDto rebind = savedBack(read, "Team");

        transactionTemplate.executeWithoutResult(status -> {
            listViewRepository.findById(UUID.fromString(read.getUuid())).orElseThrow();
            inANewTransaction(() -> listViewService.editView(read.getUuid(), rebind));
            inThisTransaction(() -> listViewService.editView(read.getUuid(), rename));
        });

        ListViewColumnDto stored = teamColumnOf(readTheOnlyView());
        Assertions.assertEquals(List.of(recreated), stored.getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, stored.getStatus());
    }

    @Test
    void aViewDeletedWhileAnEditWaitsForItsLockIsNotFound() throws Exception {
        ListViewDto created = listViewService.createView(request("Doomed", column("COMMON_NAME")));
        SecurityContext context = SecurityContextHolder.getContext();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<ListViewDto> edit = transactionTemplate.execute(status -> {
                clusterSynchronizer.lock("list-view:" + user + ":" + Resource.CERTIFICATE.getCode());
                Future<ListViewDto> waiting = executor.submit(() -> {
                    SecurityContextHolder.setContext(context);
                    try {
                        return listViewService.editView(created.getUuid(), update("Renamed", column("COMMON_NAME")));
                    } finally {
                        SecurityContextHolder.clearContext();
                    }
                });
                Awaitility
                        .await()
                        .atMost(Duration.ofSeconds(10))
                        .until(() -> jdbcTemplate
                                .queryForObject(
                                        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
                                        Long.class) >= 1);
                jdbcTemplate
                        .update("DELETE FROM " + dbSchema + ".list_view WHERE uuid = ?",
                                UUID.fromString(created.getUuid()));
                return waiting;
            });

            ExecutionException e = Assertions
                    .assertThrows(ExecutionException.class, () -> edit.get(30, TimeUnit.SECONDS));
            Assertions.assertInstanceOf(NotFoundException.class, e.getCause());
        } finally {
            executor.shutdownNow();
            Assertions.assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS));
        }
    }

    private void inANewTransaction(ListViewCall call) {
        TransactionTemplate requiresNew = new TransactionTemplate(transactionTemplate.getTransactionManager());
        requiresNew.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        requiresNew.executeWithoutResult(status -> inThisTransaction(call));
    }

    private static void inThisTransaction(ListViewCall call) {
        try {
            call.run();
        } catch (AlreadyExistException | NotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    @FunctionalInterface
    private interface ListViewCall {
        Object run() throws AlreadyExistException, NotFoundException;
    }

    @Test
    void aColumnRemovedAndAddedAgainBindsToTheCurrentDefinition()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewDto created = createTeamColumnView();
        UUID recreated = recreateTeamAttribute(team);

        listViewService.editView(created.getUuid(), update("Team", column("COMMON_NAME")));
        ListViewDto readded = listViewService
                .editView(created.getUuid(), update("Team", column("COMMON_NAME"), teamColumn()));

        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, teamColumnOf(readded).getStatus());
        Assertions.assertEquals(List.of(recreated), teamColumnOf(readded).getAttributeDefinitionUuids());
    }

    @Test
    void aChangedFilterOnARecreatedAttributeBindsToTheCurrentDefinition()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewDto created = createTeamFilterView();
        UUID recreated = recreateTeamAttribute(team);

        ListViewUpdateRequestDto edit = update("Team", column("COMMON_NAME"));
        edit.setFilters(List.of(teamFilter(FilterConditionOperator.EQUALS, "ops")));
        ListViewDto edited = listViewService.editView(created.getUuid(), edit);

        Assertions.assertEquals(List.of(recreated), edited.getFilters().getFirst().getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, edited.getFilters().getFirst().getStatus());
    }

    @Test
    void rebindingAColumnWhoseAttributeIsGoneIsRejected()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        createTeamColumnView();
        attributeService.deleteCustomAttribute(team);
        ListViewDto read = readTheOnlyView();
        teamColumnOf(read).setRebind(true);
        ListViewUpdateRequestDto rebind = savedBack(read, "Team");
        String uuid = read.getUuid();

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.editView(uuid, rebind));
        Assertions.assertTrue(e.getMessage().contains("has no field " + TEAM), e.getMessage());
    }

    @Test
    void aBindingSentByTheClientIsIgnored() throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewDto created = createTeamColumnView();
        UUID recreated = recreateTeamAttribute(team);
        ListViewColumnDto forged = teamColumn();
        forged.setAttributeDefinitionUuids(List.of(recreated));
        forged.setStatus(ListViewFieldStatus.AVAILABLE);

        ListViewDto edited = listViewService.editView(created.getUuid(), update("Team", column("COMMON_NAME"), forged));

        Assertions.assertEquals(List.of(team), teamColumnOf(edited).getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.REPLACED, teamColumnOf(edited).getStatus());
    }

    @Test
    void aNewViewIgnoresABindingSentByTheClient() throws AlreadyExistException, AttributeException {
        UUID team = createTeamAttribute();
        ListViewColumnDto forged = teamColumn();
        forged.setAttributeDefinitionUuids(List.of(UUID.randomUUID()));

        ListViewDto created = listViewService.createView(request("Team", column("COMMON_NAME"), forged));

        Assertions.assertEquals(List.of(team), teamColumnOf(created).getAttributeDefinitionUuids());
    }

    @Test
    void anOrderingOnAReplacedColumnIsDroppedOnRead()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewRequestDto request = request("Team", column("COMMON_NAME"), teamColumn());
        request.setSort(new ListViewSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.ASC));
        listViewService.createView(request);
        Assertions.assertNotNull(readTheOnlyView().getSort());

        recreateTeamAttribute(team);

        Assertions.assertNull(readTheOnlyView().getSort());
    }

    /**
     * A row written before entries carried a binding, by a replica that predates it. It resolves by identifier, as it
     * always did, and is bound to what it shows the next time the view is saved.
     */
    @Test
    void aColumnStoredWithoutABindingResolvesByIdentifierAndIsBoundOnTheNextSave()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListView stored = save("Legacy", List.of(column("COMMON_NAME"), teamColumn()),
                List.of(teamFilter(FilterConditionOperator.EQUALS, "pki")), null);

        ListViewDto read = readTheOnlyView();
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, teamColumnOf(read).getStatus());
        Assertions.assertNull(teamColumnOf(read).getAttributeDefinitionUuids());
        Assertions.assertEquals(ListViewFieldStatus.AVAILABLE, read.getFilters().getFirst().getStatus());

        ListViewDto saved = listViewService.editView(stored.getUuid().toString(), savedBack(read, "Legacy"));

        Assertions.assertEquals(List.of(team), teamColumnOf(saved).getAttributeDefinitionUuids());
        Assertions.assertEquals(List.of(team), saved.getFilters().getFirst().getAttributeDefinitionUuids());
    }

    @Test
    void aColumnBoundWhileTheAttributeWasAlreadyGoneNeverResolves() throws AlreadyExistException, AttributeException {
        ListViewColumnDto dormant = teamColumn();
        dormant.setAttributeDefinitionUuids(List.of());
        store("Dormant", List.of(column("COMMON_NAME"), dormant), null);

        createTeamAttribute();

        Assertions.assertEquals(ListViewFieldStatus.REPLACED, teamColumnOf(readTheOnlyView()).getStatus());
    }

    @Test
    void theStatusAndTheRebindFlagAreNotStored() throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        createTeamColumnView();
        recreateTeamAttribute(team);
        ListViewDto read = readTheOnlyView();
        teamColumnOf(read).setRebind(true);
        listViewService.editView(read.getUuid(), savedBack(read, "Team"));

        String columns = jdbcTemplate
                .queryForObject(
                        "SELECT CAST(\"columns\" AS TEXT) FROM " + dbSchema + ".\"list_view\" WHERE \"uuid\" = ?",
                        String.class, UUID.fromString(read.getUuid()));

        Assertions.assertFalse(columns.contains("status"), columns);
        Assertions.assertFalse(columns.contains("rebind"), columns);
        Assertions.assertTrue(columns.contains("attributeDefinitionUuids"), columns);
    }

    @Test
    void anOrderingOnAReplacedAttributeIsDroppedOnReadWithoutAColumnForIt()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewRequestDto request = request("Team", column("COMMON_NAME"));
        request.setSort(new ListViewSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.ASC));
        listViewService.createView(request);
        Assertions.assertNotNull(readTheOnlyView().getSort());

        recreateTeamAttribute(team);

        Assertions.assertNull(readTheOnlyView().getSort());
    }

    /** An ordering changed from the stored one is a choice made afresh, so it binds to the recreated attribute. */
    @Test
    void anOrderingChosenAgainAfterTheAttributeWasRecreatedIsKept()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewRequestDto request = request("Team", column("COMMON_NAME"));
        request.setSort(new ListViewSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.ASC));
        ListViewDto created = listViewService.createView(request);
        UUID recreated = recreateTeamAttribute(team);

        ListViewUpdateRequestDto edit = update("Team", column("COMMON_NAME"));
        edit.setSort(new ListViewSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.DESC));
        listViewService.editView(created.getUuid(), edit);

        Assertions.assertEquals(SortDirection.DESC, readTheOnlyView().getSort().getDirection());
        Assertions.assertEquals(List.of(recreated), storedSortBinding(created));
    }

    /**
     * A client that read the view before its attribute was replaced still holds the ordering the read now drops, and
     * sending it back unchanged must not hand it to the replacement.
     */
    @Test
    void anUnchangedOrderingSentBackByAStaleClientKeepsItsBinding()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewRequestDto request = request("Team", column("COMMON_NAME"));
        request.setSort(new ListViewSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.ASC));
        ListViewDto created = listViewService.createView(request);
        ListViewUpdateRequestDto stale = savedBack(readTheOnlyView(), "Renamed");
        recreateTeamAttribute(team);

        listViewService.editView(created.getUuid(), stale);

        Assertions.assertEquals(List.of(team), storedSortBinding(created));
        Assertions.assertEquals("Renamed", readTheOnlyView().getName());
        Assertions.assertNull(readTheOnlyView().getSort());
    }

    @Test
    void theSameOrderingChosenAgainWithRebindFollowsTheRecreatedAttribute()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListViewRequestDto request = request("Team", column("COMMON_NAME"));
        request.setSort(new ListViewSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.ASC));
        ListViewDto created = listViewService.createView(request);
        UUID recreated = recreateTeamAttribute(team);

        ListViewUpdateRequestDto edit = update("Team", column("COMMON_NAME"));
        ListViewSortRequestDto chosen = new ListViewSortRequestDto(FilterFieldSource.CUSTOM, TEAM, SortDirection.ASC);
        chosen.setRebind(true);
        edit.setSort(chosen);
        listViewService.editView(created.getUuid(), edit);

        Assertions.assertEquals(List.of(recreated), storedSortBinding(created));
        Assertions.assertEquals(SortDirection.ASC, readTheOnlyView().getSort().getDirection());
    }

    private List<UUID> storedSortBinding(ListViewDto view) {
        return listViewRepository
                .findById(UUID.fromString(view.getUuid()))
                .orElseThrow()
                .getSortAttributeDefinitionUuids();
    }

    /**
     * An attribute the owner may no longer read is out of their catalogue, so a save neither binds the entries on it to
     * anything nor lets them be rebound: the binding stays what it was until someone who can see the field saves.
     */
    @Test
    void aSaveByACallerWhoCannotReadTheAttributeLeavesItsBindingAlone()
            throws AlreadyExistException, AttributeException, NotFoundException {
        UUID team = createTeamAttribute();
        ListView stored = save("Legacy", List.of(column("COMMON_NAME"), teamColumn()),
                List.of(teamFilter(FilterConditionOperator.EQUALS, "pki")), null);
        forbidObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(team));
        ListViewDto read = readTheOnlyView();
        Assertions.assertEquals(ListViewFieldStatus.UNAVAILABLE, teamColumnOf(read).getStatus());
        Assertions.assertEquals(ListViewFieldStatus.UNAVAILABLE, read.getFilters().getFirst().getStatus());

        listViewService.editView(stored.getUuid().toString(), savedBack(read, "Legacy"));

        ListView after = listViewRepository.findById(stored.getUuid()).orElseThrow();
        Assertions.assertNull(after.getColumns().get(1).getAttributeDefinitionUuids());
        Assertions.assertNull(after.getFilters().getFirst().getAttributeDefinitionUuids());

        ListViewDto again = readTheOnlyView();
        teamColumnOf(again).setRebind(true);
        ListViewUpdateRequestDto rebind = savedBack(again, "Legacy");
        String uuid = again.getUuid();
        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.editView(uuid, rebind));
        Assertions.assertTrue(e.getMessage().contains("has no field " + TEAM), e.getMessage());
    }

    @Test
    void aUuidThatIsNotAUuidIsNotFoundRatherThanAnInternalError() {
        Assertions.assertThrows(NotFoundException.class, () -> listViewService.deleteView("not-a-uuid"));
    }

    @Test
    void anEmptyFilterListIsStoredAsNoFilterAtAll() throws AlreadyExistException {
        ListViewRequestDto request = request("Unfiltered", column("COMMON_NAME"));
        request.setFilters(List.of());

        Assertions.assertNull(listViewService.createView(request).getFilters());
    }

    @Test
    void viewsOfEveryResourceAreListedWhenNoResourceIsNamed() throws AlreadyExistException {
        listViewService.createView(request("Certificates", column("COMMON_NAME")));
        ListViewRequestDto keys = request("Keys", column("CKI_NAME"));
        keys.setResource(Resource.CRYPTOGRAPHIC_KEY);
        listViewService.createView(keys);

        Assertions
                .assertEquals(List.of("Certificates", "Keys"),
                        listViewService.listViews(null).stream().map(ListViewDto::getName).sorted().toList());
    }

    @Test
    void aColumnTheResourceDoesNotOfferIsRejectedOnWrite() {
        ListViewRequestDto request = request("Impossible", column("CKI_NAME"));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CKI_NAME"));
    }

    /**
     * The certificate listing carries no protocol value, so the field is one to filter on and never one to show.
     * Accepting it as a column would store a view whose column is empty in every row of every page.
     */
    @Test
    void aColumnTheListingCannotShowIsRejectedOnWrite() {
        ListViewRequestDto request = request("Blank", column("COMMON_NAME"), column("CERTIFICATE_PROTOCOL"));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CERTIFICATE_PROTOCOL"));
    }

    /**
     * The column gate applies to what a request introduces, not to what the view already holds. A view stored before
     * the field was withdrawn is read back carrying it, so refusing it on write would leave the view unrenamable over a
     * column the caller never touched.
     */
    @Test
    void aWithdrawnColumnTheViewAlreadyCarriesSurvivesARename() throws NotFoundException, AlreadyExistException {
        store("Legacy", List.of(column("COMMON_NAME"), column("CERTIFICATE_PROTOCOL")), null);
        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        ListViewDto renamed = listViewService
                .editView(read.getUuid(),
                        update("Legacy renamed", column("COMMON_NAME"), column("CERTIFICATE_PROTOCOL")));

        Assertions.assertEquals("Legacy renamed", renamed.getName());
        Assertions.assertEquals(List.of("COMMON_NAME", "CERTIFICATE_PROTOCOL"), identifiersOf(renamed));
    }

    /**
     * The exemption is for the columns the view carries and nothing wider: a withdrawn column can be kept or taken out,
     * never introduced, so an edit cannot do what a creation is refused.
     */
    @Test
    void aWithdrawnColumnCannotBeAddedToAnExistingView() throws AlreadyExistException {
        ListViewDto created = listViewService.createView(request("Clean", column("COMMON_NAME")));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> listViewService
                                .editView(created.getUuid(),
                                        update("Clean", column("COMMON_NAME"), column("CERTIFICATE_PROTOCOL"))));
        Assertions.assertTrue(e.getMessage().contains("CERTIFICATE_PROTOCOL"));
    }

    /**
     * A stored ordering is applied by re-issuing the listing request, and the listing refuses a field its catalogue
     * does not publish as sortable - so a view accepting one would answer an error on every application.
     */
    @Test
    void anOrderingTheListingWouldRefuseIsRejectedOnWrite() {
        ListViewRequestDto request = request("Unorderable", column("COMMON_NAME"));
        request
                .setSort(new ListViewSortRequestDto(FilterFieldSource.PROPERTY, "CERTIFICATE_PROTOCOL",
                        SortDirection.ASC));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CERTIFICATE_PROTOCOL"));
    }

    /**
     * Filtering and showing are separate capabilities: the same field the listing cannot show is one it can be filtered
     * on, and tightening the columns must not withdraw the filter with them.
     */
    @Test
    void aFilterOnAFieldTheListingCannotShowIsAccepted() throws AlreadyExistException {
        ListViewRequestDto request = request("Filtered", column("COMMON_NAME"));
        request
                .setFilters(List
                        .of(new ListViewFilterDto(FilterFieldSource.PROPERTY, "CERTIFICATE_PROTOCOL",
                                FilterConditionOperator.EQUALS, "acme")));

        ListViewDto created = listViewService.createView(request);

        Assertions.assertEquals("CERTIFICATE_PROTOCOL", created.getFilters().getFirst().getFieldIdentifier());
    }

    @Test
    void theSameColumnTwiceIsRejected() {
        ListViewRequestDto request = request("Doubled", column("COMMON_NAME"), column("COMMON_NAME", "Again"));

        Assertions.assertThrows(ValidationException.class, () -> listViewService.createView(request));
    }

    @Test
    void aResourceWithNoFieldCatalogueCannotCarryViews() {
        ListViewRequestDto request = request("Nowhere", column("COMMON_NAME"));
        request.setResource(Resource.SETTINGS);

        Assertions.assertThrows(ValidationException.class, () -> listViewService.createView(request));
    }

    /**
     * The production path loads the view into a session that stays open across the write, so the entity is managed and
     * already marked default by the time the previous default is demoted. A bulk update auto-flushes the tables it
     * touches, so an entity left attached would be written first and the partial unique index would see two defaults.
     */
    @Test
    void promotingAnAlreadyLoadedViewToDefaultKeepsOneDefault() throws AlreadyExistException {
        ListViewRequestDto first = request("First", column("COMMON_NAME"));
        first.setDefaultView(true);
        ListViewDto firstView = listViewService.createView(first);

        ListViewRequestDto second = request("Second", column("NOT_AFTER"));
        second.setDefaultView(true);
        listViewService.createView(second);

        ListViewUpdateRequestDto promoteFirst = update("First", column("COMMON_NAME"));
        promoteFirst.setDefaultView(true);
        transactionTemplate.executeWithoutResult(status -> {
            try {
                listViewService.editView(firstView.getUuid(), promoteFirst);
            } catch (AlreadyExistException | NotFoundException e) {
                throw new IllegalStateException(e);
            }
        });

        Assertions.assertEquals(List.of(firstView.getUuid()), defaultViewUuids());
    }

    /**
     * A demoted view has changed, so its audit timestamp has to move with it - the bulk update that clears the flag
     * bypasses the entity listener that would otherwise do it.
     */
    @Test
    void demotingAViewAdvancesItsAuditTimestamp() throws AlreadyExistException {
        ListViewRequestDto first = request("First", column("COMMON_NAME"));
        first.setDefaultView(true);
        ListViewDto firstView = listViewService.createView(first);
        OffsetDateTime beforeDemotion = updatedOf(firstView.getUuid());

        ListViewRequestDto second = request("Second", column("NOT_AFTER"));
        second.setDefaultView(true);
        listViewService.createView(second);

        Assertions.assertTrue(updatedOf(firstView.getUuid()).isAfter(beforeDemotion));
    }

    private OffsetDateTime updatedOf(String viewUuid) {
        return listViewRepository.findById(UUID.fromString(viewUuid)).orElseThrow().getUpdated();
    }

    /**
     * Two requests naming the same view name have to end as one view and one 409, never as an internal error: the name
     * check and the insert are serialized per user and resource, and the unique constraint behind them would otherwise
     * reject the loser with a data-integrity failure.
     */
    @Test
    void concurrentCreatesOfTheSameNameLeaveOneViewAndOneRejection() throws InterruptedException {
        SecurityContext context = SecurityContextHolder.getContext();
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger created = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            List<Future<?>> attempts = List
                    .of(executor.submit(() -> createConcurrently(context, start, created, rejected)),
                            executor.submit(() -> createConcurrently(context, start, created, rejected)));
            start.countDown();
            for (Future<?> attempt : attempts) {
                Assertions.assertDoesNotThrow(() -> attempt.get(30, TimeUnit.SECONDS));
            }
        } finally {
            executor.shutdownNow();
            Assertions.assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS));
        }

        Assertions.assertEquals(1, created.get());
        Assertions.assertEquals(1, rejected.get());
        Assertions.assertEquals(1, listViewRepository.findByUserUuidOrderByCreatedAscUuidAsc(user).size());
    }

    private void createConcurrently(SecurityContext context, CountDownLatch start, AtomicInteger created,
            AtomicInteger rejected) {
        SecurityContextHolder.setContext(context);
        try {
            start.await();
            listViewService.createView(request("Contested", column("COMMON_NAME")));
            created.incrementAndGet();
        } catch (AlreadyExistException e) {
            rejected.incrementAndGet();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void aFilterOnAFieldTheResourceDoesNotOfferIsRejectedOnWrite() {
        ListViewRequestDto request = request("Impossible", column("COMMON_NAME"));
        request
                .setFilters(List
                        .of(new ListViewFilterDto(FilterFieldSource.PROPERTY, "CKI_NAME",
                                FilterConditionOperator.EQUALS, "key")));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CKI_NAME"));
    }

    @Test
    void aFilterConditionTheFieldDoesNotOfferIsRejectedOnWrite() {
        ListViewRequestDto request = request("Impossible", column("COMMON_NAME"));
        request
                .setFilters(List
                        .of(new ListViewFilterDto(FilterFieldSource.PROPERTY, "NOT_AFTER",
                                FilterConditionOperator.CONTAINS, "test")));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CONTAINS"));
    }

    @Test
    void anOrderingOnAFieldTheResourceDoesNotOfferIsRejectedOnWrite() {
        ListViewRequestDto request = request("Impossible", column("COMMON_NAME"));
        request.setSort(new ListViewSortRequestDto(FilterFieldSource.PROPERTY, "CKI_NAME", SortDirection.ASC));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CKI_NAME"));
    }

    @Test
    void aStoredFilterAndOrderingSurviveAnEdit() throws AlreadyExistException, NotFoundException {
        ListViewDto created = listViewService.createView(request("Sliced", column("COMMON_NAME")));

        ListViewUpdateRequestDto edit = update("Sliced", column("COMMON_NAME"));
        edit
                .setFilters(List
                        .of(new ListViewFilterDto(FilterFieldSource.PROPERTY, "COMMON_NAME",
                                FilterConditionOperator.CONTAINS, "test")));
        edit.setSort(new ListViewSortRequestDto(FilterFieldSource.PROPERTY, "NOT_AFTER", SortDirection.DESC));

        ListViewDto edited = listViewService.editView(created.getUuid(), edit);

        Assertions.assertEquals("COMMON_NAME", edited.getFilters().getFirst().getFieldIdentifier());
        Assertions.assertEquals("NOT_AFTER", edited.getSort().getFieldIdentifier());
    }

    /**
     * The cleanup runs in its own transaction, so a failure in a later step of the user deletion cannot bring the rows
     * back: the user is already gone from the identity service by then, and nothing sweeps orphans afterwards.
     */
    @Test
    void viewsOfADeletedUserStayRemovedWhenTheSurroundingTransactionRollsBack() throws AlreadyExistException {
        listViewService.createView(request("Mine", column("COMMON_NAME")));

        Assertions.assertThrows(IllegalStateException.class, () -> transactionTemplate.executeWithoutResult(status -> {
            listViewInternalService.deleteViewsOfUser(user);
            throw new IllegalStateException("a later step of the deletion fails");
        }));

        Assertions.assertTrue(listViewRepository.findByUserUuidOrderByCreatedAscUuidAsc(user).isEmpty());
    }

    @Test
    void viewsOfADeletedUserAreRemovedAndOtherUsersAreLeftAlone() throws AlreadyExistException {
        listViewService.createView(request("Mine", column("COMMON_NAME")));

        authenticateAs(otherUser);
        listViewService.createView(request("Theirs", column("COMMON_NAME")));

        Assertions.assertEquals(1, listViewInternalService.deleteViewsOfUser(user));

        Assertions.assertTrue(listViewRepository.findByUserUuidOrderByCreatedAscUuidAsc(user).isEmpty());
        Assertions.assertEquals(1, listViewRepository.findByUserUuidOrderByCreatedAscUuidAsc(otherUser).size());
    }
}

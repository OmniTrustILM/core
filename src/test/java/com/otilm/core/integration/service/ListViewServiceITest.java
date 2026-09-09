package com.otilm.core.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.listview.ListViewUpdateRequestDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.ListView;
import com.otilm.core.dao.repository.ListViewRepository;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.service.ListViewExternalService;
import com.otilm.core.service.ListViewInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionTemplate;

class ListViewServiceITest extends BaseSpringBootTest {

    @Autowired
    private ListViewExternalService listViewService;

    @Autowired
    private ListViewInternalService listViewInternalService;

    @Autowired
    private ListViewRepository listViewRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private TransactionTemplate transactionTemplate;

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
        SearchFilterRequestDto filter = new SearchFilterRequestDto(FilterFieldSource.PROPERTY, "COMMON_NAME",
                FilterConditionOperator.CONTAINS, "test");
        SearchSortRequestDto sort = new SearchSortRequestDto(FilterFieldSource.PROPERTY, "NOT_AFTER",
                SortDirection.DESC);

        ListViewRequestDto request = request("Sliced", column("COMMON_NAME"));
        request.setFilters(List.of(filter));
        request.setSort(sort);

        listViewService.createView(request);

        ListViewDto stored = listViewService.listViews(Resource.CERTIFICATE).getFirst();
        Assertions.assertEquals(List.of("COMMON_NAME"), identifiersOf(stored));
        Assertions.assertEquals(1, stored.getFilters().size());
        Assertions.assertEquals("COMMON_NAME", stored.getFilters().getFirst().getFieldIdentifier());
        Assertions.assertEquals(FilterConditionOperator.CONTAINS, stored.getFilters().getFirst().getCondition());
        Assertions.assertEquals(sort, stored.getSort());
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
                .findByUserUuidOrderByNameAsc(user)
                .stream()
                .filter(ListView::isDefaultView)
                .map(view -> view.getUuid().toString())
                .toList();
    }

    /**
     * A field can leave the catalogue after a view has stored it - a custom attribute is deleted, a property is
     * retired. Reading the view then has to drop that column rather than fail, so the rest of the view keeps working.
     */
    @Test
    void aColumnWhoseFieldNoLongerExistsIsSkippedOnRead() {
        store("Stale",
                List
                        .of(column("COMMON_NAME"), column("RETIRED_FIELD"),
                                new ListViewColumnDto(FilterFieldSource.CUSTOM, "deleted|STRING", null)),
                null);

        ListViewDto read = listViewService.listViews(Resource.CERTIFICATE).getFirst();

        Assertions.assertEquals(List.of("COMMON_NAME"), identifiersOf(read));
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
        ListView stored = new ListView();
        stored.setUserUuid(user);
        stored.setResource(Resource.CERTIFICATE);
        stored.setName(name);
        stored.setColumns(columns);
        stored.setSort(sort);
        listViewRepository.save(stored);
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
                .setSort(new SearchSortRequestDto(FilterFieldSource.PROPERTY, "CERTIFICATE_PROTOCOL",
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
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, "CERTIFICATE_PROTOCOL",
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
        Assertions.assertEquals(1, listViewRepository.findByUserUuidOrderByNameAsc(user).size());
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
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, "CKI_NAME",
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
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, "NOT_AFTER",
                                FilterConditionOperator.CONTAINS, "test")));

        ValidationException e = Assertions
                .assertThrows(ValidationException.class, () -> listViewService.createView(request));
        Assertions.assertTrue(e.getMessage().contains("CONTAINS"));
    }

    @Test
    void anOrderingOnAFieldTheResourceDoesNotOfferIsRejectedOnWrite() {
        ListViewRequestDto request = request("Impossible", column("COMMON_NAME"));
        request.setSort(new SearchSortRequestDto(FilterFieldSource.PROPERTY, "CKI_NAME", SortDirection.ASC));

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
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, "COMMON_NAME",
                                FilterConditionOperator.CONTAINS, "test")));
        edit.setSort(new SearchSortRequestDto(FilterFieldSource.PROPERTY, "NOT_AFTER", SortDirection.DESC));

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

        Assertions.assertTrue(listViewRepository.findByUserUuidOrderByNameAsc(user).isEmpty());
    }

    @Test
    void viewsOfADeletedUserAreRemovedAndOtherUsersAreLeftAlone() throws AlreadyExistException {
        listViewService.createView(request("Mine", column("COMMON_NAME")));

        authenticateAs(otherUser);
        listViewService.createView(request("Theirs", column("COMMON_NAME")));

        Assertions.assertEquals(1, listViewInternalService.deleteViewsOfUser(user));

        Assertions.assertTrue(listViewRepository.findByUserUuidOrderByNameAsc(user).isEmpty());
        Assertions.assertEquals(1, listViewRepository.findByUserUuidOrderByNameAsc(otherUser).size());
    }
}

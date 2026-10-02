package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewFieldStatus;
import com.otilm.api.model.core.listview.ListViewFilterDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.listview.ListViewUpdateRequestDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.NamedField;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.ListView;
import com.otilm.core.dao.repository.ListViewRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.service.ListViewExternalService;
import com.otilm.core.service.ListViewInternalService;
import com.otilm.core.service.writer.ListViewWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.SearchHelper;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Saved list views. There is no OPA check on these operations: a view is addressed only through the user it belongs to,
 * so being authenticated as that user is the whole of the authorization. A view of another user answers 404 rather than
 * 403 - it is not addressable, not merely forbidden.
 */
@Service
public class ListViewServiceImpl implements ListViewExternalService, ListViewInternalService {

    private ListViewRepository listViewRepository;
    private ListViewWriter listViewWriter;
    private AttributeEngine attributeEngine;
    private ClusterOperationSynchronizer clusterSynchronizer;

    @Autowired
    public void setListViewRepository(ListViewRepository listViewRepository) {
        this.listViewRepository = listViewRepository;
    }

    @Autowired
    public void setListViewWriter(ListViewWriter listViewWriter) {
        this.listViewWriter = listViewWriter;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setClusterSynchronizer(ClusterOperationSynchronizer clusterSynchronizer) {
        this.clusterSynchronizer = clusterSynchronizer;
    }

    @Override
    @AnyPrincipalEndpoint
    public List<ListViewDto> listViews(Resource resource) {
        UUID userUuid = loggedUserUuid();
        List<ListView> views = resource == null
                ? listViewRepository.findByUserUuidOrderByCreatedAscUuidAsc(userUuid)
                : listViewRepository.findByUserUuidAndResourceOrderByCreatedAscUuidAsc(userUuid, resource);

        // One catalogue per resource, certain to hold every field any of its views orders by. Reading consults it for
        // the ordering alone, and naming a column whose field has left the catalogue would reload it on every read.
        // Every catalogue is narrowed by one resolution of the caller's attribute permissions.
        Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        Map<Resource, List<NamedField>> named = views
                .stream()
                .collect(Collectors
                        .groupingBy(ListView::getResource, () -> new EnumMap<>(Resource.class),
                                Collectors.flatMapping(view -> sortField(view).stream(), Collectors.toList())));
        Map<Resource, Catalogue> catalogues = new EnumMap<>(Resource.class);
        named
                .forEach((viewResource, fields) -> catalogues
                        .put(viewResource, catalogueOf(viewResource, fields, contentFilter)));
        Map<Resource, List<NamedField>> attributeFields = views
                .stream()
                .collect(Collectors
                        .groupingBy(ListView::getResource, () -> new EnumMap<>(Resource.class),
                                Collectors.flatMapping(view -> namedFields(view).stream(), Collectors.toList())));
        Map<Resource, Map<NamedField, Set<UUID>>> definitions = new EnumMap<>(Resource.class);
        attributeFields
                .forEach((viewResource, fields) -> definitions
                        .put(viewResource, attributeEngine.definitionsBehind(viewResource, fields)));
        return views
                .stream()
                .map(view -> toDto(view, catalogues.get(view.getResource()), definitions.get(view.getResource())))
                .toList();
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(rollbackFor = Exception.class)
    public ListViewDto createView(ListViewRequestDto request) throws AlreadyExistException {
        UUID userUuid = loggedUserUuid();
        Resource resource = request.getResource();
        Catalogue catalogue = catalogueOf(resource, namedFields(request),
                attributeEngine.customAttributeContentFilterOnce());
        validateRequest(resource, request, Set.of(), List.of(), catalogue);

        serializeWritesFor(userUuid, resource);
        if (listViewRepository.existsByUserUuidAndResourceAndName(userUuid, resource, request.getName())) {
            throw new AlreadyExistException(ListView.class, request.getName());
        }

        ListView view = new ListView();
        view.setUserUuid(userUuid);
        view.setResource(resource);
        Map<NamedField, Set<UUID>> definitions = attributeEngine.definitionsBehind(resource, namedFields(request));
        applyRequest(view, request, new Binder(resource, catalogue, definitions));

        return toDto(save(view, request.getName()), catalogue, definitions);
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(rollbackFor = Exception.class)
    public ListViewDto editView(String uuid, ListViewUpdateRequestDto request)
            throws NotFoundException, AlreadyExistException {
        UUID userUuid = loggedUserUuid();
        ListView view = ownView(uuid, userUuid);
        Catalogue catalogue = catalogueOf(view.getResource(), namedFields(request),
                attributeEngine.customAttributeContentFilterOnce());
        validateRequest(view.getResource(), request, columnsOf(view), filtersOf(view), catalogue);

        serializeWritesFor(userUuid, view.getResource());
        if (listViewRepository
                .existsByUserUuidAndResourceAndNameAndUuidNot(userUuid, view.getResource(), request.getName(),
                        view.getUuid())) {
            throw new AlreadyExistException(ListView.class, request.getName());
        }

        Map<NamedField, Set<UUID>> definitions = attributeEngine
                .definitionsBehind(view.getResource(), namedFields(request));
        applyRequest(view, request, new Binder(view.getResource(), catalogue, definitions));

        return toDto(save(view, request.getName()), catalogue, definitions);
    }

    @Override
    @AnyPrincipalEndpoint
    public void deleteView(String uuid) throws NotFoundException {
        listViewWriter.delete(ownView(uuid, loggedUserUuid()).getUuid());
    }

    /**
     * Runs in its own transaction, so the rows stay removed even if a later step of the user deletion this is called
     * from fails: the user is already gone from the identity service by then, and nothing sweeps orphans afterwards.
     */
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteViewsOfUser(UUID userUuid) {
        return listViewWriter.deleteAllForUser(userUuid);
    }

    /**
     * Serializes the writes of one user against one listing for the rest of the transaction. Both the unique name and
     * the single default are decided from a read taken here, and the constraints behind them turn a lost race into an
     * internal error rather than a rejection the caller can act on.
     */
    private void serializeWritesFor(UUID userUuid, Resource resource) {
        clusterSynchronizer.lock("list-view:" + userUuid + ":" + resource.getCode());
    }

    private ListView save(ListView view, String name) throws AlreadyExistException {
        try {
            return listViewWriter.save(view);
        } catch (DataIntegrityViolationException e) {
            // Backstop for the unique name, reachable only if a writer bypasses the lock above. Other integrity
            // violations are not name collisions and must surface as they are.
            if (isNameCollision(e)) {
                throw new AlreadyExistException(ListView.class, name);
            }
            throw e;
        }
    }

    private static boolean isNameCollision(DataIntegrityViolationException e) {
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException constraintViolation) {
                return ListView.UNIQUE_NAME_CONSTRAINT.equalsIgnoreCase(constraintViolation.getConstraintName());
            }
        }
        return false;
    }

    /** {@code view} still holds what was stored before this request, which is what its entries are carried from. */
    private static void applyRequest(ListView view, ListViewUpdateRequestDto request, Binder binder) {
        List<ListViewColumnDto> columns = binder.columns(request.getColumns(), view.getColumns());
        List<ListViewFilterDto> filters = binder.filters(request.getFilters(), view.getFilters());
        view.setName(request.getName());
        view.setColumns(columns);
        view.setDefaultView(request.isDefaultView());
        view.setFilters(filters.isEmpty() ? null : filters);
        view.setSort(request.getSort());
        view.setSortAttributeDefinitionUuids(binder.sort(request.getSort()));
    }

    private ListView ownView(String uuid, UUID userUuid) throws NotFoundException {
        UUID viewUuid;
        try {
            viewUuid = UUID.fromString(uuid);
        } catch (IllegalArgumentException e) {
            throw new NotFoundException(ListView.class, uuid);
        }
        return listViewRepository
                .findByUuidAndUserUuid(viewUuid, userUuid)
                .orElseThrow(() -> new NotFoundException(ListView.class, uuid));
    }

    private static UUID loggedUserUuid() {
        return UUID.fromString(AuthHelper.getUserIdentification().getUuid());
    }

    private static ListViewDto toDto(ListView view, Catalogue catalogue, Map<NamedField, Set<UUID>> definitions) {
        ListViewDto dto = new ListViewDto();
        dto.setUuid(view.getUuid().toString());
        dto.setName(view.getName());
        dto.setResource(view.getResource());
        dto.setDefaultView(view.isDefaultView());
        // Every stored column is returned, including one whose field the listing can no longer show, that has left
        // the catalogue outright or that a later definition now answers for, with a status saying which. Withholding
        // it instead would let the client's next full-row write erase it without the user ever having seen it, when
        // the field may yet come back.
        List<ListViewColumnDto> columns = view
                .getColumns()
                .stream()
                .map(column -> resolvedColumn(column, catalogue, definitions))
                .toList();
        dto.setColumns(columns);
        dto
                .setFilters(view.getFilters() == null
                        ? null
                        : view
                                .getFilters()
                                .stream()
                                .map(filter -> resolvedFilter(filter, catalogue, definitions))
                                .toList());
        // Returning an ordering the listing would now refuse hands the client a view whose every application answers
        // an error; dropping it opens the view in the listing's own order instead. An ordering whose attribute is now
        // backed by other definitions would order the listing by values nobody chose, so it is dropped the same way.
        SearchSortRequestDto sort = view.getSort();
        dto
                .setSort(sort != null && catalogue.canSortBy(CatalogueField.of(sort))
                        && statusOf(CatalogueField.of(sort), view.getSortAttributeDefinitionUuids(), catalogue,
                                definitions) == ListViewFieldStatus.AVAILABLE ? sort : null);
        return dto;
    }

    private static ListViewColumnDto resolvedColumn(ListViewColumnDto stored, Catalogue catalogue,
            Map<NamedField, Set<UUID>> definitions) {
        ListViewColumnDto column = new ListViewColumnDto(stored.getFieldSource(), stored.getFieldIdentifier(),
                stored.getLabel());
        column.setAttributeDefinitionUuids(stored.getAttributeDefinitionUuids());
        column
                .setStatus(statusOf(CatalogueField.of(stored), stored.getAttributeDefinitionUuids(), catalogue,
                        definitions));
        return column;
    }

    private static ListViewFilterDto resolvedFilter(ListViewFilterDto stored, Catalogue catalogue,
            Map<NamedField, Set<UUID>> definitions) {
        ListViewFilterDto filter = new ListViewFilterDto(stored.getFieldSource(), stored.getFieldIdentifier(),
                stored.getCondition(), stored.getValue());
        filter.setAttributeDefinitionUuids(stored.getAttributeDefinitionUuids());
        filter
                .setStatus(statusOf(CatalogueField.of(stored), stored.getAttributeDefinitionUuids(), catalogue,
                        definitions));
        return filter;
    }

    /**
     * The catalogue may be a replica's cached copy, so a field with no definition behind it any more is unavailable
     * even while the catalogue still lists it. An entry stored without a binding was written before entries carried
     * one, and resolves by its identifier alone as it always did until a save binds it.
     */
    private static ListViewFieldStatus statusOf(CatalogueField field, List<UUID> binding, Catalogue catalogue,
            Map<NamedField, Set<UUID>> definitions) {
        if (!catalogue.offers(field)) {
            return ListViewFieldStatus.UNAVAILABLE;
        }
        if (!field.named().isAttribute()) {
            return ListViewFieldStatus.AVAILABLE;
        }
        Set<UUID> current = definitions.getOrDefault(field.named(), Set.of());
        if (current.isEmpty()) {
            return ListViewFieldStatus.UNAVAILABLE;
        }
        if (binding == null) {
            return ListViewFieldStatus.AVAILABLE;
        }
        return intersects(binding, current) ? ListViewFieldStatus.AVAILABLE : ListViewFieldStatus.REPLACED;
    }

    private static boolean intersects(List<UUID> binding, Set<UUID> definitions) {
        return binding.stream().anyMatch(definitions::contains);
    }

    private static boolean isRebind(ListViewColumnDto column) {
        return Boolean.TRUE.equals(column.getRebind());
    }

    private static boolean isRebind(ListViewFilterDto filter) {
        return Boolean.TRUE.equals(filter.getRebind());
    }

    /**
     * Takes the stored filter a requested one carries over, if any, out of {@code pool}. Each stored filter is carried
     * by one requested filter at most, and only by one sent with the same terms and without {@code rebind}.
     */
    private static ListViewFilterDto takeCarried(List<ListViewFilterDto> pool, ListViewFilterDto requested) {
        if (isRebind(requested)) {
            return null;
        }
        FilterTerm term = FilterTerm.of(requested);
        for (int i = 0; i < pool.size(); i++) {
            if (FilterTerm.of(pool.get(i)).equals(term)) {
                return pool.remove(i);
            }
        }
        return null;
    }

    /**
     * Binds the entries of a request to the attribute definitions behind them, which is what lets a read tell the
     * definition an entry was added for from one created later under the same name and content type.
     *
     * <p>
     * A new entry, or one sent with {@code rebind}, is bound to the current definitions. The validation before has held
     * it to the catalogue, but that may be a replica's stale copy, so a field with no definition behind it is refused
     * here as a missing one. An entry carried over from the stored view keeps its binding while that no longer
     * resolves, so saving a view back unchanged never adopts a replacement. While it still resolves it is bound to the
     * current definitions, so it follows definitions registered under the same identifier alongside the ones it was
     * bound to. Bindings change only for a field the caller is offered, so an entry on an attribute the caller may not
     * read is stored as it was.
     */
    private record Binder(Resource resource, Catalogue catalogue, Map<NamedField, Set<UUID>> definitions) {

        /**
         * A stored ordering that no longer resolves is never returned, so an ordering a client sends is its own choice
         * made afresh rather than one carried over, and is bound to the current definitions.
         */
        List<UUID> sort(SearchSortRequestDto sort) {
            return sort == null ? null : bindingOf(CatalogueField.of(sort), null, false);
        }

        List<ListViewColumnDto> columns(List<ListViewColumnDto> requested, List<ListViewColumnDto> stored) {
            Map<CatalogueField, ListViewColumnDto> carriable = stored == null
                    ? Map.of()
                    : stored
                            .stream()
                            .collect(Collectors.toMap(CatalogueField::of, column -> column, (first, next) -> first));
            List<ListViewColumnDto> bound = new ArrayList<>();
            for (ListViewColumnDto column : requested) {
                ListViewColumnDto carried = isRebind(column) ? null : carriable.get(CatalogueField.of(column));
                ListViewColumnDto entry = new ListViewColumnDto(column.getFieldSource(), column.getFieldIdentifier(),
                        column.getLabel());
                entry
                        .setAttributeDefinitionUuids(bindingOf(CatalogueField.of(column),
                                carried == null ? null : carried.getAttributeDefinitionUuids(), carried != null));
                bound.add(entry);
            }
            return bound;
        }

        List<ListViewFilterDto> filters(List<ListViewFilterDto> requested, List<ListViewFilterDto> stored) {
            if (requested == null) {
                return List.of();
            }
            List<ListViewFilterDto> pool = stored == null ? new ArrayList<>() : new ArrayList<>(stored);
            List<ListViewFilterDto> bound = new ArrayList<>();
            for (ListViewFilterDto filter : requested) {
                ListViewFilterDto carried = takeCarried(pool, filter);
                ListViewFilterDto entry = new ListViewFilterDto(filter.getFieldSource(), filter.getFieldIdentifier(),
                        filter.getCondition(), filter.getValue());
                entry
                        .setAttributeDefinitionUuids(bindingOf(CatalogueField.of(filter),
                                carried == null ? null : carried.getAttributeDefinitionUuids(), carried != null));
                bound.add(entry);
            }
            return bound;
        }

        private List<UUID> bindingOf(CatalogueField field, List<UUID> storedBinding, boolean carried) {
            if (!field.named().isAttribute()) {
                return null;
            }
            List<UUID> current = definitions.getOrDefault(field.named(), Set.of()).stream().sorted().toList();
            if (!carried) {
                if (current.isEmpty()) {
                    rejectUnknown(resource, List.of(field.fieldIdentifier()));
                }
                return current;
            }
            boolean resolves = storedBinding == null || intersects(storedBinding, Set.copyOf(current));
            return catalogue.offers(field) && !current.isEmpty() && resolves ? current : storedBinding;
        }
    }

    /**
     * Rejects anything the resource's catalogue cannot apply, so a view is stored only in a shape the listing can
     * actually use.
     *
     * <p>
     * {@code carriedAlready} are the columns the stored view holds, which are exempt from the column gates. A field can
     * stop being one the listing shows, or leave the catalogue outright, after a view stored it, and rejecting it would
     * leave that view unsaveable: the client reads it back, renames it, and the rename is refused over a column it did
     * not touch. So such a column can be kept or removed but not introduced, and a creation - which carries nothing
     * already - is held to the current catalogue in full.
     *
     * <p>
     * {@code filtersCarried} are the filters the stored view holds, and one sent back unchanged is exempt on the same
     * terms. Its field may have left the catalogue, or stayed in it but stopped offering the stored condition - a
     * hidden or encrypted custom attribute accepts only presence conditions - and either way a view could not be
     * renamed. The exemption covers the stored filter exactly, so a new or changed filter, or a second copy of a stored
     * one, is held to the catalogue.
     *
     * <p>
     * An ordering has no such exemption. It is applied by re-issuing the listing request, which refuses a field that is
     * not sortable, so keeping one would answer an error on every application rather than show a blank column. Such an
     * ordering is dropped on read instead.
     */
    private static void validateRequest(Resource resource, ListViewUpdateRequestDto request,
            Set<CatalogueField> carriedAlready, List<ListViewFilterDto> filtersCarried, Catalogue catalogue) {
        if (catalogue.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("Resource %s has no field catalogue and cannot carry views."
                            .formatted(resource.getCode())));
        }

        validateColumns(resource, request.getColumns(), catalogue, carriedAlready);
        validateFilters(resource, request.getFilters(), catalogue, filtersCarried);
        validateSort(resource, request.getSort(), catalogue);
    }

    private static Set<CatalogueField> columnsOf(ListView view) {
        return view.getColumns().stream().map(CatalogueField::of).collect(Collectors.toUnmodifiableSet());
    }

    private static List<ListViewFilterDto> filtersOf(ListView view) {
        return view.getFilters() == null ? List.of() : List.copyOf(view.getFilters());
    }

    private static void validateColumns(Resource resource, List<ListViewColumnDto> columns, Catalogue catalogue,
            Set<CatalogueField> carriedAlready) {
        Set<CatalogueField> seen = new LinkedHashSet<>();
        List<String> duplicated = columns
                .stream()
                .filter(column -> !seen.add(CatalogueField.of(column)))
                .map(ListViewColumnDto::getFieldIdentifier)
                .toList();
        if (!duplicated.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("A column can appear only once in a view: %s".formatted(String.join(", ", duplicated))));
        }

        rejectUnknown(resource,
                columns
                        .stream()
                        .filter(column -> isRebind(column) || !carriedAlready.contains(CatalogueField.of(column)))
                        .filter(column -> !catalogue.offers(CatalogueField.of(column)))
                        .map(ListViewColumnDto::getFieldIdentifier)
                        .toList());

        List<String> unshowable = columns
                .stream()
                .filter(column -> isRebind(column) || !carriedAlready.contains(CatalogueField.of(column)))
                .filter(column -> !catalogue.canDisplay(CatalogueField.of(column)))
                .map(ListViewColumnDto::getFieldIdentifier)
                .toList();
        if (!unshowable.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("Resource %s does not offer these fields as columns: %s."
                            .formatted(resource.getCode(), String.join(", ", unshowable))));
        }
    }

    /**
     * A filter has to name a field of this resource and an operator that field accepts, because the listing resolves
     * both against the same catalogue when the view is applied: a filter naming another resource's field, or an
     * operator the field has no expression for, would fail there rather than here.
     */
    private static void validateFilters(Resource resource, List<ListViewFilterDto> requested, Catalogue catalogue,
            List<ListViewFilterDto> filtersCarried) {
        if (requested == null) {
            return;
        }

        List<ListViewFilterDto> uncarried = new ArrayList<>(filtersCarried);
        List<ListViewFilterDto> filters = new ArrayList<>();
        for (ListViewFilterDto filter : requested) {
            if (takeCarried(uncarried, filter) == null) {
                filters.add(filter);
            }
        }

        rejectUnknown(resource,
                filters
                        .stream()
                        .filter(filter -> !catalogue.offers(CatalogueField.of(filter)))
                        .map(ListViewFilterDto::getFieldIdentifier)
                        .toList());

        List<String> unsupported = filters
                .stream()
                .filter(filter -> !catalogue.accepts(CatalogueField.of(filter), filter.getCondition()))
                .map(filter -> "%s %s".formatted(filter.getFieldIdentifier(), filter.getCondition().getCode()))
                .toList();
        if (!unsupported.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("Resource %s does not offer these filter conditions: %s."
                            .formatted(resource.getCode(), String.join(", ", unsupported))));
        }
    }

    private static void validateSort(Resource resource, SearchSortRequestDto sort, Catalogue catalogue) {
        if (sort == null) {
            return;
        }
        if (!catalogue.offers(CatalogueField.of(sort))) {
            rejectUnknown(resource, List.of(sort.getFieldIdentifier()));
        }
        if (!catalogue.canSortBy(CatalogueField.of(sort))) {
            throw new ValidationException(ValidationError
                    .create("Resource %s cannot be ordered by %s."
                            .formatted(resource.getCode(), sort.getFieldIdentifier())));
        }
    }

    private static void rejectUnknown(Resource resource, List<String> unknown) {
        if (!unknown.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("Resource %s has no field %s.".formatted(resource.getCode(), String.join(", ", unknown))));
        }
    }

    /**
     * Every field the resource's listing can address, with what each of them may be used for. Properties come from the
     * filter-field enum, everything else from the attribute definitions currently registered for the resource.
     *
     * <p>
     * Read from the published catalogue rather than from a copy of its rules, so the flags the client picked a view out
     * of and the answer it gets back when it saves one cannot disagree. Each attribute field in {@code named} that
     * exists and the caller may read is in it, even one registered on another replica since this one cached the
     * catalogue.
     */
    private Catalogue catalogueOf(Resource resource, Collection<NamedField> named,
            Supplier<CustomAttributeContentFilter> contentFilter) {
        Map<CatalogueField, Capabilities> fields = new HashMap<>();
        FilterField
                .getEnumsForResource(resource)
                .forEach(field -> fields
                        .put(new CatalogueField(FilterFieldSource.PROPERTY, field.name()),
                                new Capabilities(SearchHelper.availableConditions(field),
                                        SearchHelper.isDisplayable(field), SearchHelper.isSortableField(field))));
        attributeEngine
                .getResourceSearchableFields(resource, false, named, contentFilter)
                .forEach(group -> group
                        .getSearchFieldData()
                        .forEach(field -> fields
                                .put(new CatalogueField(group.getFilterFieldSource(), field.getFieldIdentifier()),
                                        new Capabilities(field.getConditions(),
                                                Boolean.TRUE.equals(field.getDisplayable()),
                                                Boolean.TRUE.equals(field.getSortable())))));
        return new Catalogue(fields);
    }

    private static Optional<NamedField> sortField(ListView view) {
        return Optional
                .ofNullable(view.getSort())
                .map(sort -> NamedField.of(sort.getFieldSource(), sort.getFieldIdentifier()));
    }

    private static List<NamedField> namedFields(ListView view) {
        List<NamedField> named = new ArrayList<>();
        view.getColumns().forEach(column -> named.add(CatalogueField.of(column).named()));
        if (view.getFilters() != null) {
            view.getFilters().forEach(filter -> named.add(CatalogueField.of(filter).named()));
        }
        sortField(view).ifPresent(named::add);
        return named;
    }

    private static List<NamedField> namedFields(ListViewUpdateRequestDto request) {
        List<NamedField> named = new ArrayList<>();
        if (request.getColumns() != null) {
            request
                    .getColumns()
                    .forEach(column -> named.add(NamedField.of(column.getFieldSource(), column.getFieldIdentifier())));
        }
        if (request.getFilters() != null) {
            request
                    .getFilters()
                    .forEach(filter -> named.add(NamedField.of(filter.getFieldSource(), filter.getFieldIdentifier())));
        }
        if (request.getSort() != null) {
            named.add(NamedField.of(request.getSort().getFieldSource(), request.getSort().getFieldIdentifier()));
        }
        return named;
    }

    /** What makes two filters the same filter: the field, the condition and the value, whatever their binding. */
    private record FilterTerm(FilterFieldSource fieldSource, String fieldIdentifier, FilterConditionOperator condition,
            Object value) {

        static FilterTerm of(ListViewFilterDto filter) {
            return new FilterTerm(filter.getFieldSource(), filter.getFieldIdentifier(), filter.getCondition(),
                    filter.getValue());
        }
    }

    /**
     * What one field of a catalogue may be used for. The three are separate capabilities rather than one membership: a
     * listing filters on values it does not select - a certificate is found by its protocol without the listing
     * carrying one - and orders only by the values it shows.
     */
    private record Capabilities(List<FilterConditionOperator> conditions, boolean displayable, boolean sortable) {
    }

    private record Catalogue(Map<CatalogueField, Capabilities> fields) {

        boolean isEmpty() {
            return fields.isEmpty();
        }

        boolean offers(CatalogueField field) {
            return fields.containsKey(field);
        }

        boolean canDisplay(CatalogueField field) {
            Capabilities capabilities = fields.get(field);
            return capabilities != null && capabilities.displayable();
        }

        boolean canSortBy(CatalogueField field) {
            Capabilities capabilities = fields.get(field);
            return capabilities != null && capabilities.sortable();
        }

        boolean accepts(CatalogueField field, FilterConditionOperator condition) {
            Capabilities capabilities = fields.get(field);
            return capabilities != null && capabilities.conditions() != null
                    && capabilities.conditions().contains(condition);
        }
    }

    private record CatalogueField(FilterFieldSource fieldSource, String fieldIdentifier) {

        NamedField named() {
            return NamedField.of(fieldSource, fieldIdentifier);
        }

        static CatalogueField of(ListViewColumnDto column) {
            return new CatalogueField(column.getFieldSource(), column.getFieldIdentifier());
        }

        static CatalogueField of(ListViewFilterDto filter) {
            return new CatalogueField(filter.getFieldSource(), filter.getFieldIdentifier());
        }

        static CatalogueField of(SearchSortRequestDto sort) {
            return new CatalogueField(sort.getFieldSource(), sort.getFieldIdentifier());
        }
    }
}

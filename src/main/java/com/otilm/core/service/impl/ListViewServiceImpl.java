package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.listview.ListViewUpdateRequestDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine;
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
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
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
                ? listViewRepository.findByUserUuidOrderByNameAsc(userUuid)
                : listViewRepository.findByUserUuidAndResourceOrderByNameAsc(userUuid, resource);

        Map<Resource, Catalogue> catalogues = new EnumMap<>(Resource.class);
        return views.stream().map(view -> toDto(view, catalogues)).toList();
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(rollbackFor = Exception.class)
    public ListViewDto createView(ListViewRequestDto request) throws AlreadyExistException {
        UUID userUuid = loggedUserUuid();
        Resource resource = request.getResource();
        validateRequest(resource, request, Set.of());

        serializeWritesFor(userUuid, resource);
        if (listViewRepository.existsByUserUuidAndResourceAndName(userUuid, resource, request.getName())) {
            throw new AlreadyExistException(ListView.class, request.getName());
        }

        ListView view = new ListView();
        view.setUserUuid(userUuid);
        view.setResource(resource);
        applyRequest(view, request);

        return toDto(save(view, request.getName()), new EnumMap<>(Resource.class));
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(rollbackFor = Exception.class)
    public ListViewDto editView(String uuid, ListViewUpdateRequestDto request)
            throws NotFoundException, AlreadyExistException {
        UUID userUuid = loggedUserUuid();
        ListView view = ownView(uuid, userUuid);
        validateRequest(view.getResource(), request, columnsOf(view));

        serializeWritesFor(userUuid, view.getResource());
        if (listViewRepository
                .existsByUserUuidAndResourceAndNameAndUuidNot(userUuid, view.getResource(), request.getName(),
                        view.getUuid())) {
            throw new AlreadyExistException(ListView.class, request.getName());
        }

        applyRequest(view, request);

        return toDto(save(view, request.getName()), new EnumMap<>(Resource.class));
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

    private static void applyRequest(ListView view, ListViewUpdateRequestDto request) {
        view.setName(request.getName());
        view.setColumns(request.getColumns());
        view.setDefaultView(request.isDefaultView());
        view.setFilters(request.getFilters() == null || request.getFilters().isEmpty() ? null : request.getFilters());
        view.setSort(request.getSort());
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

    private ListViewDto toDto(ListView view, Map<Resource, Catalogue> catalogues) {
        Catalogue catalogue = catalogues.computeIfAbsent(view.getResource(), this::catalogueOf);

        ListViewDto dto = new ListViewDto();
        dto.setUuid(view.getUuid().toString());
        dto.setName(view.getName());
        dto.setResource(view.getResource());
        dto.setDefaultView(view.isDefaultView());
        // A column the listing can no longer show is still returned: the client has the same catalogue this is read
        // from, so it can mark the column unavailable and offer to remove it, and a view whose every column was
        // withdrawn still reads back in a shape it can be saved in. Only a field that has left the catalogue outright
        // is dropped, having nothing left to label it with.
        dto
                .setColumns(view
                        .getColumns()
                        .stream()
                        .filter(column -> catalogue.offers(CatalogueField.of(column)))
                        .toList());
        dto.setFilters(view.getFilters());
        // Returning an ordering the listing would now refuse hands the client a view whose every application answers
        // an error; dropping it opens the view in the listing's own order instead.
        dto
                .setSort(view.getSort() != null && catalogue.canSortBy(CatalogueField.of(view.getSort()))
                        ? view.getSort()
                        : null);
        return dto;
    }

    /**
     * Rejects anything the resource's catalogue cannot apply, so a view is stored only in a shape the listing can
     * actually use.
     *
     * <p>
     * {@code carriedAlready} are the columns the stored view holds, which are exempt from the column gate. A field can
     * stop being one the listing shows after a view stored it, and rejecting it would leave that view unsaveable: the
     * client reads it back, renames it, and the rename is refused over a column it did not touch. So a withdrawn column
     * can be kept or removed but not introduced, and a creation - which carries nothing already - is held to the
     * current catalogue in full.
     *
     * <p>
     * An ordering has no such exemption. It is applied by re-issuing the listing request, which refuses a field that is
     * not sortable, so keeping one would answer an error on every application rather than show a blank column. Such an
     * ordering is dropped on read instead.
     */
    private void validateRequest(Resource resource, ListViewUpdateRequestDto request,
            Set<CatalogueField> carriedAlready) {
        Catalogue catalogue = catalogueOf(resource);
        if (catalogue.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("Resource %s has no field catalogue and cannot carry views."
                            .formatted(resource.getCode())));
        }

        validateColumns(resource, request.getColumns(), catalogue, carriedAlready);
        validateFilters(resource, request.getFilters(), catalogue);
        validateSort(resource, request.getSort(), catalogue);
    }

    private static Set<CatalogueField> columnsOf(ListView view) {
        return view.getColumns().stream().map(CatalogueField::of).collect(Collectors.toUnmodifiableSet());
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
                        .filter(column -> !catalogue.offers(CatalogueField.of(column)))
                        .map(ListViewColumnDto::getFieldIdentifier)
                        .toList());

        List<String> unshowable = columns
                .stream()
                .filter(column -> !carriedAlready.contains(CatalogueField.of(column)))
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
    private static void validateFilters(Resource resource, List<SearchFilterRequestDto> filters, Catalogue catalogue) {
        if (filters == null) {
            return;
        }

        rejectUnknown(resource,
                filters
                        .stream()
                        .filter(filter -> !catalogue.offers(CatalogueField.of(filter)))
                        .map(SearchFilterRequestDto::getFieldIdentifier)
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
     * of and the answer it gets back when it saves one cannot disagree.
     */
    private Catalogue catalogueOf(Resource resource) {
        Map<CatalogueField, Capabilities> fields = new HashMap<>();
        FilterField
                .getEnumsForResource(resource)
                .forEach(field -> fields
                        .put(new CatalogueField(FilterFieldSource.PROPERTY, field.name()),
                                new Capabilities(SearchHelper.availableConditions(field),
                                        SearchHelper.isDisplayable(field), SearchHelper.isSortableField(field))));
        attributeEngine
                .getResourceSearchableFields(resource, false)
                .forEach(group -> group
                        .getSearchFieldData()
                        .forEach(field -> fields
                                .put(new CatalogueField(group.getFilterFieldSource(), field.getFieldIdentifier()),
                                        new Capabilities(field.getConditions(),
                                                Boolean.TRUE.equals(field.getDisplayable()),
                                                Boolean.TRUE.equals(field.getSortable())))));
        return new Catalogue(fields);
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

        static CatalogueField of(ListViewColumnDto column) {
            return new CatalogueField(column.getFieldSource(), column.getFieldIdentifier());
        }

        static CatalogueField of(SearchFilterRequestDto filter) {
            return new CatalogueField(filter.getFieldSource(), filter.getFieldIdentifier());
        }

        static CatalogueField of(SearchSortRequestDto sort) {
            return new CatalogueField(sort.getFieldSource(), sort.getFieldIdentifier());
        }
    }
}

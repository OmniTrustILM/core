package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.exception.DanglingReferenceException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;

/**
 * One resolution of the references in a connector request, shared by callback mode and system mode so that both resolve
 * the same objects the same way. They differ in the loaders, which carry the authorization.
 *
 * <p>
 * A RESOURCE reference is replaced in place by the content the request's loader returns. The {@link ReferenceLending}
 * is asked for every loaded object whether its references are resolved, and with which loader; an object it declines
 * keeps them bare at any depth. A reference more than {@link #MAX_DEPTH} levels below the request fails the whole
 * resolution rather than reach the connector unresolved.
 *
 * <p>
 * Each object is loaded at most once per resolution. A later reference to an object resolved earlier gets the same
 * content, except that an object the request names itself is always checked through the request's loader, even when
 * lending reached it first. A reference to an object whose own references are still being resolved closes a loop and
 * stays a bare reference, since that object's content already sits higher up on the same path.
 *
 * <p>
 * A refusal names the reference it stopped at: a missing object as a {@link DanglingReferenceException}, a denied one
 * as a {@link ReferenceAccessDeniedException}.
 */
final class ReferenceTraversal {

    /** How many levels below the request a reference may sit. */
    static final int MAX_DEPTH = 3;

    /** Where a reference sits: the attribute holding it, and the object that attribute belongs to, if any. */
    private record Holder(String attribute, ResourceObjectContentData object) {
    }

    private final ReferenceLoader requestLoader;
    private final ReferenceLending lending;
    private final Map<String, ResourceObjectContentData> resolved = new HashMap<>();
    private final Set<String> inProgress = new HashSet<>();
    private final Set<String> checkedForRequest = new HashSet<>();

    /**
     * @param requestLoader loads the objects the request refers to itself
     * @param lending decides whether, and with which loader, the references inside each of those objects are resolved
     */
    ReferenceTraversal(ReferenceLoader requestLoader, ReferenceLending lending) {
        this.requestLoader = requestLoader;
        this.lending = lending;
    }

    /** Resolves the references in the content of one request attribute, and everything they nest. */
    void resolve(String attributeName, Object content)
            throws NotFoundException, AttributeException, ConnectorException {
        Holder holder = new Holder(attributeName, null);
        for (ResourceObjectContent reference : referencesIn(content)) {
            resolve(reference, holder, 0, requestLoader);
        }
    }

    /**
     * Resolves what the objects in the content of one request attribute nest, when those objects were loaded already.
     * System mode loads the request's own references through {@code ResourceInternalService} first, which names the
     * attribute of a reference whose object is gone.
     */
    void resolveInsideLoaded(Object content) throws NotFoundException, AttributeException, ConnectorException {
        for (ResourceObjectContent reference : referencesIn(content)) {
            ResourceObjectContentData loaded = reference.getData();
            if (!identifiesAnObject(loaded)) {
                continue;
            }
            String key = key(loaded.getResource(), uuidOf(loaded));
            ResourceObjectContentData known = resolved.get(key);
            if (known != null) {
                reference.setData(known);
            } else {
                resolveLent(key, loaded, 0);
            }
        }
    }

    private void resolve(ResourceObjectContent reference, Holder holder, int depth, ReferenceLoader loader)
            throws NotFoundException, AttributeException, ConnectorException {
        ResourceObjectContentData target = reference.getData();
        if (!identifiesAnObject(target)) {
            return;
        }
        UUID uuid = uuidOf(target);
        String key = key(target.getResource(), uuid);
        if (inProgress.contains(key)) {
            return;
        }
        ResourceObjectContentData known = resolved.get(key);
        if (known != null) {
            if (depth == 0 && checkedForRequest.add(key)) {
                load(loader, target, uuid, holder);
            }
            reference.setData(known);
            return;
        }
        if (depth > MAX_DEPTH) {
            throw ReferenceExpansionException.depthExceeded(describe(target, holder), MAX_DEPTH);
        }
        ResourceObjectContentData loaded = load(loader, target, uuid, holder);
        if (loaded == null) {
            return;
        }
        if (depth == 0) {
            checkedForRequest.add(key);
        }
        if (loaded.getUuid() == null) {
            loaded.setUuid(uuid.toString());
        }
        if (loaded.getName() == null) {
            loaded.setName(target.getName());
        }
        reference.setData(loaded);
        resolveLent(key, loaded, depth);
    }

    /** Resolves what a loaded object nests, when it lends that, with the loader it lends it through. */
    private void resolveLent(String key, ResourceObjectContentData lender, int depth)
            throws NotFoundException, AttributeException, ConnectorException {
        ReferenceLoader lent = lending.insideOf(lender.getResource(), uuidOf(lender));
        if (lent == null) {
            resolved.put(key, lender);
        } else {
            resolveNested(key, lender, depth, lent);
        }
    }

    private void resolveNested(String key, ResourceObjectContentData loaded, int depth, ReferenceLoader loader)
            throws NotFoundException, AttributeException, ConnectorException {
        inProgress.add(key);
        if (loaded instanceof ResourceSimpleContentData object && object.getAttributes() != null) {
            for (ResponseAttribute attribute : object.getAttributes()) {
                Holder holder = new Holder(Objects.requireNonNullElse(attribute.getLabel(), attribute.getName()),
                        object);
                for (ResourceObjectContent nested : referencesIn(attribute.getContent())) {
                    resolve(nested, holder, depth + 1, loader);
                }
            }
        }
        inProgress.remove(key);
        resolved.put(key, loaded);
    }

    private static ResourceObjectContentData load(ReferenceLoader loader, ResourceObjectContentData target, UUID uuid,
            Holder holder) throws NotFoundException, AttributeException, ConnectorException {
        try {
            return loader.load(target.getResource(), uuid);
        } catch (DanglingReferenceException e) {
            throw e;
        } catch (NotFoundException e) {
            throw new DanglingReferenceException("%s refers to %s, which does not exist. Select another one."
                    .formatted(describeHolder(holder), describe(target)));
        } catch (AccessDeniedException e) {
            throw new ReferenceAccessDeniedException(describe(target, holder), e);
        }
    }

    private static boolean identifiesAnObject(ResourceObjectContentData data) {
        return data != null && data.getResource() != null && data.getUuid() != null;
    }

    private static UUID uuidOf(ResourceObjectContentData reference) throws AttributeException {
        try {
            return UUID.fromString(reference.getUuid());
        } catch (IllegalArgumentException e) {
            // The UUID comes from the caller's request or from stored content, so it is safe to name.
            throw new AttributeException("Malformed RESOURCE reference UUID: " + reference.getUuid());
        }
    }

    private static List<ResourceObjectContent> referencesIn(Object content) {
        List<ResourceObjectContent> references = new ArrayList<>();
        if (content instanceof List<?> items) {
            for (Object item : items) {
                if (item instanceof ResourceObjectContent reference) {
                    references.add(reference);
                }
            }
        }
        return references;
    }

    /** The object a reference names, as its kind and its name, or its UUID when the reference carries no name. */
    private static String describe(ResourceObjectContentData reference) {
        String nameOrUuid = Objects.requireNonNullElse(reference.getName(), reference.getUuid());
        return "%s '%s'".formatted(reference.getResource().getLabel(), nameOrUuid);
    }

    private static String describe(ResourceObjectContentData reference, Holder holder) {
        if (holder.object() == null) {
            return describe(reference);
        }
        return "%s in attribute '%s' of %s"
                .formatted(describe(reference), holder.attribute(), describe(holder.object()));
    }

    private static String describeHolder(Holder holder) {
        if (holder.object() == null) {
            return "Attribute '%s'".formatted(holder.attribute());
        }
        return "Attribute '%s' of %s".formatted(holder.attribute(), describe(holder.object()));
    }

    /**
     * The key of an object on one resolution: its kind and its UUID, never the UUID alone, as objects of two kinds may
     * share one.
     */
    static String key(AttributeResource kind, UUID uuid) {
        return kind.name() + ":" + uuid;
    }
}

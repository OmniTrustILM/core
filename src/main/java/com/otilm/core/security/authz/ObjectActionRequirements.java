package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.ComplianceProfile;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.Proxy;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.TimeQualityConfiguration;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.model.auth.ResourceAction;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * What the endpoints acting on one object require for each action they perform, written out by hand because the
 * authorization annotations do not say which object a check protects: some endpoints check the object, some only the
 * resource, and some check a parent object or a related one, such as a certificate's RA profile. Where several
 * endpoints perform the same action on an object and require different things, the entry holds all of them, so an
 * action is reported only when every one of those endpoints would accept it.
 *
 * <p>
 * Keep an entry in step with the endpoints it describes: when an endpoint's authorization changes, change its entry.
 */
public final class ObjectActionRequirements {

    /** A condition an action on the object requires. */
    public sealed interface Requirement permits OnObject, OnObjectUnder, OnResource, OnAncestor, OnLinked {
    }

    /**
     * The action on the object itself, where ownership and object grants apply, and for list and detail also the
     * members action on a group the object is assigned to.
     */
    public record OnObject(ResourceAction action) implements Requirement {
    }

    /**
     * The action on the object asked together with an action on the object the entity attribute names, the way an
     * endpoint annotated with a parent resource asks it: the parent is checked first, and ownership and group-members
     * access still admit the object when that check fails.
     */
    public record OnObjectUnder(ResourceAction action, Resource parent, String parentAttribute,
            ResourceAction parentAction) implements Requirement {
    }

    /**
     * The action on a resource as a whole, for endpoints that take the object's UUID without checking the object. The
     * resource is the object's own unless one is named.
     */
    public record OnResource(Resource resource, ResourceAction action) implements Requirement {

        public OnResource(ResourceAction action) {
            this(null, action);
        }
    }

    /** The action on an ancestor of the object, such as the authority of an RA profile; refused when it has none. */
    public record OnAncestor(Resource ancestor, ResourceAction action) implements Requirement {
    }

    /**
     * The action on the object whose UUID the entity attribute holds, such as a key's token. When the attribute is
     * empty the requirement is met if the endpoints check the object only when it is set, and refused otherwise.
     */
    public record OnLinked(Resource resource, String attribute, ResourceAction action,
            boolean metWhenEmpty) implements Requirement {

        static OnLinked ifSet(Resource resource, String attribute, ResourceAction action) {
            return new OnLinked(resource, attribute, action, true);
        }

        static OnLinked required(Resource resource, String attribute, ResourceAction action) {
            return new OnLinked(resource, attribute, action, false);
        }
    }

    /**
     * How the objects of one resource are stored, how the list endpoints admit one, and what each reported action
     * requires.
     *
     * @param entity entity holding the objects, used to tell whether an object exists
     * @param parent resource of the object's parent, or {@link Resource#NONE}
     * @param parentAttribute entity attribute holding the parent's UUID, or {@code null} without a parent
     * @param listing what the list endpoints require for the object to be listed
     */
    public record ResourceObjects(Class<?> entity, Resource parent, String parentAttribute, Requirement listing,
            Map<ResourceAction, List<Requirement>> actions) {
    }

    private static final Map<Resource, ResourceObjects> TABLE = new EnumMap<>(Resource.class);

    private static final OnObject LISTED = new OnObject(ResourceAction.LIST);

    static {
        onObject(Resource.CREDENTIAL, Credential.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.CONNECTOR, Connector.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.APPROVE, ResourceAction.CONNECT);
        onResource(Resource.ATTRIBUTE, AttributeDefinition.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.PROXY, Proxy.class, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE,
                ResourceAction.GET_PROXY_INSTALLATION);
        onObject(Resource.ACME_PROFILE, AcmeProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.SCEP_PROFILE, ScepProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.CMP_PROFILE, CmpProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.AUTHORITY, AuthorityInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        underParent(Resource.RA_PROFILE, RaProfile.class, Resource.AUTHORITY, "authorityInstanceReferenceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        alsoOnObject(Resource.RA_PROFILE, ResourceAction.CHECK_COMPLIANCE, ResourceAction.MEMBERS);
        onObject(Resource.GROUP, Group.class, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE,
                ResourceAction.MEMBERS);
        onObject(Resource.COMPLIANCE_PROFILE, ComplianceProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.CHECK_COMPLIANCE);
        onObject(Resource.ENTITY, EntityInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        underParent(Resource.LOCATION, Location.class, Resource.ENTITY, "entityInstanceReferenceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.TOKEN, TokenInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ACTIVATE, ResourceAction.MEMBERS);
        underParent(Resource.TOKEN_PROFILE, TokenProfile.class, Resource.TOKEN, "tokenInstanceReferenceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        alsoOnObject(Resource.TOKEN_PROFILE, ResourceAction.MEMBERS);
        onResource(Resource.VAULT, VaultInstance.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        underParent(Resource.VAULT_PROFILE, VaultProfile.class, Resource.VAULT, "vaultInstanceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        alsoOnObject(Resource.VAULT_PROFILE, ResourceAction.MEMBERS);
        onObject(Resource.SIGNING_PROFILE, SigningProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.TIME_QUALITY_CONFIGURATION, TimeQualityConfiguration.class, ResourceAction.DETAIL,
                ResourceAction.UPDATE, ResourceAction.DELETE);
        onObject(Resource.TSP_PROFILE, TspProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE, ResourceAction.TIMESTAMP);
        underParent(Resource.TSP_PROFILE_BASIC_CREDENTIAL, TspProfileBasicCredential.class, Resource.TSP_PROFILE,
                "tspProfileUuid", ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE);

        // Every secret endpoint loads the secret through a check of members on its source vault profile.
        OnLinked sourceVaultProfileMembers = OnLinked
                .ifSet(Resource.VAULT_PROFILE, "sourceVaultProfileUuid", ResourceAction.MEMBERS);
        Map<ResourceAction, List<Requirement>> secret = new LinkedHashMap<>();
        for (ResourceAction action : List
                .of(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE,
                        ResourceAction.GET_SECRET_CONTENT)) {
            secret.put(action, List.of(new OnResource(action), sourceVaultProfileMembers));
        }
        TABLE
                .put(Resource.SECRET,
                        new ResourceObjects(
                                Secret.class, Resource.NONE, null, new OnObjectUnder(ResourceAction.LIST,
                                        Resource.VAULT_PROFILE, "sourceVaultProfileUuid", ResourceAction.MEMBERS),
                                secret));

        // Certificate detail, update and delete also check members on the RA profile. Renew, issue and revoke check
        // the resource and the RA profile and authority they run under. Rekey checks renew, so it has no entry.
        OnObjectUnder inRaProfile = new OnObjectUnder(ResourceAction.DETAIL, Resource.RA_PROFILE, "raProfileUuid",
                ResourceAction.MEMBERS);
        OnAncestor raProfileDetail = new OnAncestor(Resource.RA_PROFILE, ResourceAction.DETAIL);
        OnAncestor authorityDetail = new OnAncestor(Resource.AUTHORITY, ResourceAction.DETAIL);
        Map<ResourceAction, List<Requirement>> certificate = new LinkedHashMap<>();
        for (ResourceAction action : List.of(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE)) {
            certificate.put(action, List.of(new OnObject(action), inRaProfile));
        }
        certificate.put(ResourceAction.ARCHIVE, List.of(new OnObject(ResourceAction.ARCHIVE)));
        certificate
                .put(ResourceAction.CHECK_COMPLIANCE,
                        List
                                .of(new OnObject(ResourceAction.CHECK_COMPLIANCE), inRaProfile,
                                        new OnResource(Resource.COMPLIANCE_PROFILE, ResourceAction.CHECK_COMPLIANCE)));
        certificate
                .put(ResourceAction.RENEW,
                        List
                                .of(new OnResource(ResourceAction.RENEW), new OnResource(ResourceAction.CREATE),
                                        raProfileDetail, authorityDetail));
        certificate
                .put(ResourceAction.ISSUE,
                        List
                                .of(new OnResource(ResourceAction.ISSUE), new OnResource(ResourceAction.CREATE),
                                        raProfileDetail, authorityDetail));
        certificate
                .put(ResourceAction.REVOKE,
                        List.of(new OnResource(ResourceAction.REVOKE), raProfileDetail, authorityDetail));
        certificate
                .put(ResourceAction.COMMENT, List
                        .of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL), inRaProfile));
        TABLE
                .put(Resource.CERTIFICATE,
                        new ResourceObjects(Certificate.class, Resource.RA_PROFILE, "raProfileUuid",
                                new OnObjectUnder(ResourceAction.LIST, Resource.RA_PROFILE, "raProfileUuid",
                                        ResourceAction.MEMBERS),
                                certificate));

        // Key detail includes the event history, and key update the compromise and usage endpoints, which check only
        // the resource. The key endpoints also check the key's token in code, export also its token profile, and the
        // operations with a key run through its token profile, which they check first.
        OnLinked tokenDetail = OnLinked.ifSet(Resource.TOKEN, "tokenInstanceReferenceUuid", ResourceAction.DETAIL);
        OnLinked tokenMembers = OnLinked.ifSet(Resource.TOKEN, "tokenInstanceReferenceUuid", ResourceAction.MEMBERS);
        OnLinked tokenProfileDetail = OnLinked.ifSet(Resource.TOKEN_PROFILE, "tokenProfileUuid", ResourceAction.DETAIL);
        Map<ResourceAction, List<Requirement>> key = new LinkedHashMap<>();
        key
                .put(ResourceAction.DETAIL, List
                        .of(new OnObject(ResourceAction.DETAIL), new OnResource(ResourceAction.DETAIL), tokenMembers));
        key
                .put(ResourceAction.UPDATE,
                        List
                                .of(new OnObject(ResourceAction.UPDATE), new OnResource(ResourceAction.UPDATE),
                                        tokenDetail, tokenMembers));
        key
                .put(ResourceAction.DELETE,
                        List
                                .of(new OnObject(ResourceAction.DELETE), new OnResource(ResourceAction.DELETE),
                                        tokenDetail, tokenMembers));
        key.put(ResourceAction.ENABLE, List.of(new OnResource(ResourceAction.ENABLE), tokenDetail));
        key
                .put(ResourceAction.EXPORT_KEY,
                        List
                                .of(new OnResource(ResourceAction.EXPORT_KEY), new OnObject(ResourceAction.DETAIL),
                                        tokenProfileDetail, tokenDetail, tokenMembers));
        OnLinked operationTokenProfile = OnLinked
                .required(Resource.TOKEN_PROFILE, "tokenProfileUuid", ResourceAction.DETAIL);
        for (ResourceAction action : List
                .of(ResourceAction.ENCRYPT, ResourceAction.DECRYPT, ResourceAction.SIGN, ResourceAction.VERIFY)) {
            key
                    .put(action,
                            List
                                    .of(new OnResource(action), operationTokenProfile,
                                            new OnAncestor(Resource.TOKEN, ResourceAction.DETAIL)));
        }
        key
                .put(ResourceAction.COMMENT, List
                        .of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL), tokenMembers));
        TABLE
                .put(Resource.CRYPTOGRAPHIC_KEY,
                        new ResourceObjects(CryptographicKey.class, Resource.TOKEN, "tokenInstanceReferenceUuid",
                                new OnObjectUnder(ResourceAction.LIST, Resource.TOKEN, "tokenInstanceReferenceUuid",
                                        ResourceAction.MEMBERS),
                                key));

        secret
                .put(ResourceAction.COMMENT,
                        List
                                .of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL),
                                        sourceVaultProfileMembers));
        // Commenting loads the host object through its detail check.
        for (Resource commentable : Resource.getCommentableResources()) {
            ResourceObjects objects = TABLE.get(commentable);
            if (objects != null && !objects.actions().containsKey(ResourceAction.COMMENT)) {
                objects
                        .actions()
                        .put(ResourceAction.COMMENT,
                                List.of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL)));
            }
        }
        TABLE
                .replaceAll((resource, objects) -> new ResourceObjects(objects.entity(), objects.parent(),
                        objects.parentAttribute(), objects.listing(), Collections.unmodifiableMap(objects.actions())));
    }

    private ObjectActionRequirements() {
    }

    public static Optional<ResourceObjects> of(Resource resource) {
        return Optional.ofNullable(TABLE.get(resource));
    }

    static Map<Resource, ResourceObjects> all() {
        return Map.copyOf(TABLE);
    }

    private static void onObject(Resource resource, Class<?> entity, ResourceAction... actions) {
        register(resource, entity, Resource.NONE, null, actions, action -> List.of(new OnObject(action)));
    }

    private static void alsoOnObject(Resource resource, ResourceAction... actions) {
        for (ResourceAction action : actions) {
            TABLE.get(resource).actions().put(action, List.of(new OnObject(action)));
        }
    }

    private static void onResource(Resource resource, Class<?> entity, ResourceAction... actions) {
        register(resource, entity, Resource.NONE, null, actions, action -> List.of(new OnResource(action)));
    }

    private static void underParent(Resource resource, Class<?> entity, Resource parent, String parentAttribute,
            ResourceAction... actions) {
        register(resource, entity, parent, parentAttribute, actions,
                action -> List.of(new OnObject(action), new OnAncestor(parent, ResourceAction.DETAIL)));
    }

    private static void register(Resource resource, Class<?> entity, Resource parent, String parentAttribute,
            ResourceAction[] actions, Function<ResourceAction, List<Requirement>> requirements) {
        Map<ResourceAction, List<Requirement>> byAction = new LinkedHashMap<>();
        for (ResourceAction action : actions) {
            byAction.put(action, requirements.apply(action));
        }
        TABLE.put(resource, new ResourceObjects(entity, parent, parentAttribute, LISTED, byAction));
    }
}

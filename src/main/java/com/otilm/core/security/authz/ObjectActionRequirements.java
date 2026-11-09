package com.otilm.core.security.authz;

import com.otilm.api.model.common.attribute.common.AttributeType;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
    public sealed interface Requirement
            permits OnObject, OnObjectUnder, OnResource, OnAncestor, OnLinked, OnLinkedThrough, WhenEmpty, OnEachChild {
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
     * The requirement evaluated against the object whose UUID the entity attribute holds instead of this object, such
     * as members on the vault profile of the secret a credential keeps its password in. Refused when the attribute is
     * empty.
     */
    public record OnLinkedThrough(Resource through, String attribute, Requirement requirement) implements Requirement {
    }

    /** The requirement only when the entity attribute is empty, such as for a token without a connector interface. */
    public record WhenEmpty(String attribute, Requirement requirement) implements Requirement {
    }

    /**
     * The requirements evaluated against every object of the child resource whose entity attribute holds this object's
     * UUID, such as the basic credentials of a TSP profile. When there is none, the requirements for no child are
     * evaluated against this object instead, for endpoints that still check the resource with an empty batch.
     */
    public record OnEachChild(Resource child, String childAttribute, List<Requirement> requirements,
            List<Requirement> whenNone) implements Requirement {

        public OnEachChild(Resource child, String childAttribute, List<Requirement> requirements) {
            this(child, childAttribute, requirements, List.of());
        }
    }

    /**
     * How the objects of one resource are stored, how the list and detail endpoints admit one, and what each reported
     * action requires.
     *
     * @param entity entity holding the objects, used to tell whether an object exists
     * @param parent resource of the object's parent, or {@link Resource#NONE}
     * @param parentAttribute entity attribute holding the parent's UUID, or {@code null} without a parent
     * @param listing what the list endpoints require for the object to be listed
     * @param viewing the least an endpoint loading the object by its UUID alone requires, which can be less than every
     * endpoint reporting detail asks for
     * @param admitted entity attribute values an object must have for the endpoints to act on it, such as the attribute
     * definition types they expose; empty when every object of the entity is acted on
     */
    public record ResourceObjects(Class<?> entity, Resource parent, String parentAttribute, List<Requirement> listing,
            List<Requirement> viewing, Map<ResourceAction, List<Requirement>> actions,
            Map<String, Set<Object>> admitted) {
    }

    private static final String UUID_ATTRIBUTE = "uuid";

    private static final String CONNECTOR_UUID = "connectorUuid";

    private static final String RA_PROFILE_UUID = "raProfileUuid";

    private static final String TOKEN_UUID = "tokenInstanceReferenceUuid";

    private static final String TOKEN_PROFILE_UUID = "tokenProfileUuid";

    private static final String SOURCE_VAULT_PROFILE_UUID = "sourceVaultProfileUuid";

    private static final String TSP_PROFILE_UUID = "tspProfileUuid";

    private static final String SECRET_UUID = "secretUuid";

    private static final Map<Resource, ResourceObjects> TABLE = new EnumMap<>(Resource.class);

    private static final List<Requirement> LISTED = List.of(new OnObject(ResourceAction.LIST));

    static {
        onObject(Resource.CREDENTIAL, Credential.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        also(Resource.CREDENTIAL, ResourceAction.UPDATE,
                OnLinked.required(Resource.CONNECTOR, CONNECTOR_UUID, ResourceAction.ANY));
        onObject(Resource.CONNECTOR, Connector.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.APPROVE, ResourceAction.CONNECT);
        // The attribute endpoints act on custom attributes and metadata, never on connector data definitions.
        onResource(Resource.ATTRIBUTE, AttributeDefinition.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        also(Resource.ATTRIBUTE, ResourceAction.DETAIL, new OnObject(ResourceAction.DETAIL));
        admit(Resource.ATTRIBUTE, "type", AttributeType.CUSTOM, AttributeType.META);
        viewedThroughObjectDetail(Resource.ATTRIBUTE);
        onObject(Resource.PROXY, Proxy.class, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE,
                ResourceAction.GET_PROXY_INSTALLATION);
        // Deleting an ACME or CMP profile first lists the RA profiles using it. Force deleting an ACME profile also
        // detaches it from them in one update check of those RA profiles, asked on the resource when there are none.
        onObject(Resource.ACME_PROFILE, AcmeProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        also(Resource.ACME_PROFILE, ResourceAction.DELETE, new OnResource(Resource.RA_PROFILE, ResourceAction.LIST),
                new OnEachChild(Resource.RA_PROFILE, "acmeProfileUuid", List.of(new OnObject(ResourceAction.UPDATE)),
                        List.of(new OnResource(Resource.RA_PROFILE, ResourceAction.UPDATE))));
        onObject(Resource.SCEP_PROFILE, ScepProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.CMP_PROFILE, CmpProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        also(Resource.CMP_PROFILE, ResourceAction.DELETE, new OnResource(Resource.RA_PROFILE, ResourceAction.LIST));
        // Updating an authority or entity loads its connector and the credentials its attributes name.
        onObject(Resource.AUTHORITY, AuthorityInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        also(Resource.AUTHORITY, ResourceAction.UPDATE,
                OnLinked.required(Resource.CONNECTOR, CONNECTOR_UUID, ResourceAction.DETAIL),
                new OnResource(Resource.CREDENTIAL, ResourceAction.DETAIL));
        // An RA profile detached from its authority, and a token profile without a token, are still read and deleted
        // through endpoints that check the parent only when there is one.
        underParent(Resource.RA_PROFILE, RaProfile.class, Resource.AUTHORITY, "authorityInstanceReferenceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        parentWhenSet(Resource.RA_PROFILE, ResourceAction.DETAIL, ResourceAction.DELETE);
        // The RA profile detail endpoint taking only its UUID does not check the authority.
        viewedThroughObjectDetail(Resource.RA_PROFILE);
        alsoOnObject(Resource.RA_PROFILE, ResourceAction.CHECK_COMPLIANCE, ResourceAction.MEMBERS);
        also(Resource.RA_PROFILE, ResourceAction.CHECK_COMPLIANCE,
                new OnResource(Resource.COMPLIANCE_PROFILE, ResourceAction.CHECK_COMPLIANCE));
        onObject(Resource.GROUP, Group.class, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE,
                ResourceAction.MEMBERS);
        // Adding or removing a compliance group returns the profile through its detail check.
        onObject(Resource.COMPLIANCE_PROFILE, ComplianceProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.CHECK_COMPLIANCE);
        also(Resource.COMPLIANCE_PROFILE, ResourceAction.UPDATE, new OnObject(ResourceAction.DETAIL));
        onObject(Resource.ENTITY, EntityInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        also(Resource.ENTITY, ResourceAction.UPDATE,
                OnLinked.required(Resource.CONNECTOR, CONNECTOR_UUID, ResourceAction.ANY),
                new OnResource(Resource.CREDENTIAL, ResourceAction.DETAIL));
        underParent(Resource.LOCATION, Location.class, Resource.ENTITY, "entityInstanceReferenceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        // Updating a token whose provider has no connector interface also updates it in the connector, loading the
        // credentials its attributes name.
        onObject(Resource.TOKEN, TokenInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ACTIVATE, ResourceAction.MEMBERS);
        also(Resource.TOKEN, ResourceAction.UPDATE,
                new WhenEmpty("connectorInterfaceUuid", new OnResource(Resource.CREDENTIAL, ResourceAction.DETAIL)));
        // The bulk token profile endpoints check token detail on the resource as a whole.
        underParent(Resource.TOKEN_PROFILE, TokenProfile.class, Resource.TOKEN, TOKEN_UUID, ResourceAction.DETAIL,
                ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        parentWhenSet(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, ResourceAction.DELETE);
        for (ResourceAction action : List.of(ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE)) {
            also(Resource.TOKEN_PROFILE, action, new OnResource(Resource.TOKEN, ResourceAction.DETAIL));
        }
        TABLE
                .get(Resource.TOKEN_PROFILE)
                .actions()
                .put(ResourceAction.MEMBERS,
                        List
                                .of(new OnObjectUnder(ResourceAction.MEMBERS, Resource.TOKEN, TOKEN_UUID,
                                        ResourceAction.MEMBERS)));
        // Vault detail and update have endpoints checking the resource and others checking the object, and update
        // loads the vault's connector.
        onResource(Resource.VAULT, VaultInstance.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        also(Resource.VAULT, ResourceAction.DETAIL, new OnObject(ResourceAction.DETAIL));
        also(Resource.VAULT, ResourceAction.UPDATE, new OnObject(ResourceAction.UPDATE),
                OnLinked.required(Resource.CONNECTOR, CONNECTOR_UUID, ResourceAction.DETAIL));
        viewedThroughObjectDetail(Resource.VAULT);
        underParent(Resource.VAULT_PROFILE, VaultProfile.class, Resource.VAULT, "vaultInstanceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        alsoOnObject(Resource.VAULT_PROFILE, ResourceAction.MEMBERS);
        // Listing a vault profile's secret attributes loads the connector of its vault.
        OnLinkedThrough vaultConnectorDetail = new OnLinkedThrough(Resource.VAULT, "vaultInstanceUuid",
                OnLinked.required(Resource.CONNECTOR, CONNECTOR_UUID, ResourceAction.DETAIL));
        also(Resource.VAULT_PROFILE, ResourceAction.DETAIL, vaultConnectorDetail);
        // Signing profile detail includes its signing records, and deleting one first lists the TSP profiles using it
        // as their default, checking TSP profile list against the signing profile's UUID.
        onObject(Resource.SIGNING_PROFILE, SigningProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        also(Resource.SIGNING_PROFILE, ResourceAction.DETAIL, new OnResource(ResourceAction.DETAIL),
                new OnResource(Resource.SIGNING_RECORD, ResourceAction.LIST));
        also(Resource.SIGNING_PROFILE, ResourceAction.DELETE, new OnResource(ResourceAction.DETAIL),
                OnLinked.required(Resource.TSP_PROFILE, UUID_ATTRIBUTE, ResourceAction.LIST));
        // Time quality configuration and TSP profile lookups of the signing profiles using them check signing profile
        // list. A TSP profile timestamps by name, through loaders checking detail on both resources.
        onObject(Resource.TIME_QUALITY_CONFIGURATION, TimeQualityConfiguration.class, ResourceAction.DETAIL,
                ResourceAction.UPDATE, ResourceAction.DELETE);
        also(Resource.TIME_QUALITY_CONFIGURATION, ResourceAction.DETAIL,
                new OnResource(Resource.SIGNING_PROFILE, ResourceAction.LIST));
        also(Resource.TIME_QUALITY_CONFIGURATION, ResourceAction.DELETE, new OnObject(ResourceAction.DETAIL),
                new OnResource(Resource.SIGNING_PROFILE, ResourceAction.LIST));
        onObject(Resource.TSP_PROFILE, TspProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE, ResourceAction.TIMESTAMP);
        also(Resource.TSP_PROFILE, ResourceAction.ENABLE, new OnObject(ResourceAction.DETAIL));
        also(Resource.TSP_PROFILE, ResourceAction.DELETE, new OnObject(ResourceAction.DETAIL),
                new OnResource(Resource.SIGNING_PROFILE, ResourceAction.LIST));
        // Deleting a TSP profile deletes the secret of each of its basic credentials.
        also(Resource.TSP_PROFILE, ResourceAction.DELETE,
                new OnEachChild(Resource.TSP_PROFILE_BASIC_CREDENTIAL, TSP_PROFILE_UUID,
                        List
                                .of(new OnResource(Resource.SECRET, ResourceAction.DELETE),
                                        new OnLinkedThrough(Resource.SECRET, SECRET_UUID,
                                                OnLinked
                                                        .ifSet(Resource.VAULT_PROFILE, SOURCE_VAULT_PROFILE_UUID,
                                                                ResourceAction.MEMBERS)))));
        also(Resource.TSP_PROFILE, ResourceAction.TIMESTAMP, new OnResource(ResourceAction.DETAIL),
                new OnResource(Resource.SIGNING_PROFILE, ResourceAction.DETAIL));

        // Every secret endpoint loads the secret through a check of members on its source vault profile. Detail,
        // update and content each have endpoints checking the resource and others checking the object.
        OnLinked sourceVaultProfileMembers = OnLinked
                .ifSet(Resource.VAULT_PROFILE, SOURCE_VAULT_PROFILE_UUID, ResourceAction.MEMBERS);
        Map<ResourceAction, List<Requirement>> secret = new LinkedHashMap<>();
        for (ResourceAction action : List.of(ResourceAction.DELETE, ResourceAction.ENABLE)) {
            secret.put(action, List.of(new OnResource(action), sourceVaultProfileMembers));
        }
        for (ResourceAction action : List
                .of(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.GET_SECRET_CONTENT)) {
            secret.put(action, List.of(new OnResource(action), new OnObject(action), sourceVaultProfileMembers));
        }
        // Reading the content and updating a secret go through the connector of its source vault profile's vault.
        OnLinkedThrough sourceVaultConnectorDetail = new OnLinkedThrough(Resource.VAULT_PROFILE,
                SOURCE_VAULT_PROFILE_UUID, vaultConnectorDetail);
        for (ResourceAction action : List.of(ResourceAction.UPDATE, ResourceAction.GET_SECRET_CONTENT)) {
            List<Requirement> combined = new ArrayList<>(secret.get(action));
            combined.add(sourceVaultConnectorDetail);
            secret.put(action, List.copyOf(combined));
        }
        secret
                .put(ResourceAction.COMMENT,
                        List
                                .of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL),
                                        sourceVaultProfileMembers));
        TABLE
                .put(Resource.SECRET, new ResourceObjects(Secret.class, Resource.NONE, null,
                        List
                                .of(new OnObjectUnder(ResourceAction.LIST, Resource.VAULT_PROFILE,
                                        SOURCE_VAULT_PROFILE_UUID, ResourceAction.MEMBERS)),
                        List.of(new OnObject(ResourceAction.DETAIL), sourceVaultProfileMembers), secret, Map.of()));

        // A basic credential is listed and read with the name of the user it maps to, and keeps its password in a
        // secret, which update rotates and delete removes.
        OnResource userDetail = new OnResource(Resource.USER, ResourceAction.DETAIL);
        OnAncestor tspProfileDetail = new OnAncestor(Resource.TSP_PROFILE, ResourceAction.DETAIL);
        underParent(Resource.TSP_PROFILE_BASIC_CREDENTIAL, TspProfileBasicCredential.class, Resource.TSP_PROFILE,
                TSP_PROFILE_UUID, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE);
        also(Resource.TSP_PROFILE_BASIC_CREDENTIAL, ResourceAction.DETAIL, userDetail);
        also(Resource.TSP_PROFILE_BASIC_CREDENTIAL, ResourceAction.UPDATE, userDetail,
                new OnResource(Resource.SECRET, ResourceAction.UPDATE),
                new OnLinkedThrough(Resource.SECRET, SECRET_UUID, sourceVaultProfileMembers));
        also(Resource.TSP_PROFILE_BASIC_CREDENTIAL, ResourceAction.DELETE,
                new OnResource(Resource.SECRET, ResourceAction.DELETE),
                new OnLinkedThrough(Resource.SECRET, SECRET_UUID, sourceVaultProfileMembers));
        ResourceObjects basicCredential = TABLE.get(Resource.TSP_PROFILE_BASIC_CREDENTIAL);
        TABLE
                .put(Resource.TSP_PROFILE_BASIC_CREDENTIAL, new ResourceObjects(basicCredential.entity(),
                        basicCredential.parent(), basicCredential.parentAttribute(),
                        List.of(new OnResource(ResourceAction.LIST), tspProfileDetail, userDetail),
                        basicCredential.actions().get(ResourceAction.DETAIL), basicCredential.actions(), Map.of()));

        // Certificate detail, update and delete also check members on the RA profile, and bulk delete detail on it.
        // Detail includes the certificate's locations, read through the location list, and delete removes the
        // certificate from its locations through a location update check asked against the certificate's UUID.
        // Renew, issue and revoke check the resource and the RA profile and authority they run under, and issue loads
        // the certificate through its detail check. Rekey checks renew, so it has no entry.
        OnObjectUnder inRaProfile = new OnObjectUnder(ResourceAction.DETAIL, Resource.RA_PROFILE, RA_PROFILE_UUID,
                ResourceAction.MEMBERS);
        OnAncestor raProfileDetail = new OnAncestor(Resource.RA_PROFILE, ResourceAction.DETAIL);
        OnAncestor authorityDetail = new OnAncestor(Resource.AUTHORITY, ResourceAction.DETAIL);
        Map<ResourceAction, List<Requirement>> certificate = new LinkedHashMap<>();
        certificate
                .put(ResourceAction.DETAIL,
                        List
                                .of(new OnObject(ResourceAction.DETAIL), inRaProfile,
                                        new OnResource(Resource.LOCATION, ResourceAction.LIST)));
        certificate.put(ResourceAction.UPDATE, List.of(new OnObject(ResourceAction.UPDATE), inRaProfile));
        certificate
                .put(ResourceAction.DELETE,
                        List
                                .of(new OnObject(ResourceAction.DELETE), inRaProfile,
                                        new OnObjectUnder(ResourceAction.DELETE, Resource.RA_PROFILE, RA_PROFILE_UUID,
                                                ResourceAction.DETAIL),
                                        OnLinked.required(Resource.LOCATION, UUID_ATTRIBUTE, ResourceAction.UPDATE)));
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
                .put(ResourceAction.ISSUE, List
                        .of(new OnResource(ResourceAction.ISSUE), new OnResource(ResourceAction.CREATE),
                                raProfileDetail, authorityDetail, new OnObject(ResourceAction.DETAIL), inRaProfile));
        certificate
                .put(ResourceAction.REVOKE,
                        List.of(new OnResource(ResourceAction.REVOKE), raProfileDetail, authorityDetail));
        certificate
                .put(ResourceAction.COMMENT, List
                        .of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL), inRaProfile));
        TABLE
                .put(Resource.CERTIFICATE,
                        new ResourceObjects(Certificate.class, Resource.RA_PROFILE, RA_PROFILE_UUID,
                                List
                                        .of(new OnObjectUnder(ResourceAction.LIST, Resource.RA_PROFILE, RA_PROFILE_UUID,
                                                ResourceAction.MEMBERS)),
                                List.of(new OnObject(ResourceAction.DETAIL), inRaProfile), certificate, Map.of()));

        // Key detail includes the event history, and key update the compromise and usage endpoints, which check only
        // the resource. The bulk key endpoints check token detail, and inventory removal token members, on the
        // resource as a whole, and deleting key items filters them by members on their token profile. The key
        // endpoints also check the key's token in code and export also its token profile. The operations with a key
        // check the operation against the UUID of the token profile they run through, then detail on that profile.
        OnLinked tokenDetail = OnLinked.ifSet(Resource.TOKEN, TOKEN_UUID, ResourceAction.DETAIL);
        OnLinked tokenMembers = OnLinked.ifSet(Resource.TOKEN, TOKEN_UUID, ResourceAction.MEMBERS);
        OnLinked tokenProfileDetail = OnLinked.ifSet(Resource.TOKEN_PROFILE, TOKEN_PROFILE_UUID, ResourceAction.DETAIL);
        OnResource anyTokenDetail = new OnResource(Resource.TOKEN, ResourceAction.DETAIL);
        Map<ResourceAction, List<Requirement>> key = new LinkedHashMap<>();
        key
                .put(ResourceAction.DETAIL, List
                        .of(new OnObject(ResourceAction.DETAIL), new OnResource(ResourceAction.DETAIL), tokenMembers));
        key
                .put(ResourceAction.UPDATE, List
                        .of(new OnObject(ResourceAction.UPDATE), new OnResource(ResourceAction.UPDATE),
                                new OnObject(ResourceAction.DETAIL), anyTokenDetail, tokenDetail, tokenMembers));
        key
                .put(ResourceAction.DELETE,
                        List
                                .of(new OnObject(ResourceAction.DELETE), new OnResource(ResourceAction.DELETE),
                                        anyTokenDetail, new OnResource(Resource.TOKEN, ResourceAction.MEMBERS),
                                        new OnObjectUnder(ResourceAction.DELETE, Resource.TOKEN_PROFILE,
                                                TOKEN_PROFILE_UUID, ResourceAction.MEMBERS),
                                        tokenDetail, tokenMembers));
        key.put(ResourceAction.ENABLE, List.of(new OnResource(ResourceAction.ENABLE), anyTokenDetail, tokenDetail));
        key
                .put(ResourceAction.EXPORT_KEY,
                        List
                                .of(new OnResource(ResourceAction.EXPORT_KEY), new OnObject(ResourceAction.DETAIL),
                                        tokenProfileDetail, tokenDetail, tokenMembers));
        for (ResourceAction action : List
                .of(ResourceAction.ENCRYPT, ResourceAction.DECRYPT, ResourceAction.SIGN, ResourceAction.VERIFY)) {
            key
                    .put(action, List
                            .of(OnLinked.required(Resource.CRYPTOGRAPHIC_KEY, TOKEN_PROFILE_UUID, action), OnLinked
                                    .required(Resource.TOKEN_PROFILE, TOKEN_PROFILE_UUID, ResourceAction.DETAIL),
                                    new OnAncestor(Resource.TOKEN, ResourceAction.DETAIL)));
        }
        key
                .put(ResourceAction.COMMENT, List
                        .of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL), tokenMembers));
        TABLE
                .put(Resource.CRYPTOGRAPHIC_KEY,
                        new ResourceObjects(CryptographicKey.class, Resource.TOKEN, TOKEN_UUID,
                                List
                                        .of(new OnObjectUnder(ResourceAction.LIST, Resource.TOKEN, TOKEN_UUID,
                                                ResourceAction.MEMBERS)),
                                List.of(new OnObject(ResourceAction.DETAIL), tokenMembers), key, Map.of()));

        // Commenting loads the host object through its detail check, which also checks detail on its parent if set.
        for (Resource commentable : Resource.getCommentableResources()) {
            ResourceObjects objects = TABLE.get(commentable);
            if (objects != null && !objects.actions().containsKey(ResourceAction.COMMENT)) {
                List<Requirement> comment = new ArrayList<>(
                        List.of(new OnObject(ResourceAction.COMMENT), new OnObject(ResourceAction.DETAIL)));
                if (objects.parent() != Resource.NONE) {
                    comment.add(OnLinked.ifSet(objects.parent(), objects.parentAttribute(), ResourceAction.DETAIL));
                }
                objects.actions().put(ResourceAction.COMMENT, List.copyOf(comment));
            }
        }
        TABLE
                .replaceAll((resource, objects) -> new ResourceObjects(objects.entity(), objects.parent(),
                        objects.parentAttribute(), objects.listing(), objects.viewing(),
                        Collections.unmodifiableMap(objects.actions()), objects.admitted()));
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

    private static void also(Resource resource, ResourceAction action, Requirement... requirements) {
        Map<ResourceAction, List<Requirement>> actions = TABLE.get(resource).actions();
        List<Requirement> combined = new ArrayList<>(actions.get(action));
        combined.addAll(List.of(requirements));
        actions.put(action, List.copyOf(combined));
    }

    /**
     * Replaces the parent check of the actions, and of viewing when detail is among them, with one met when the object
     * has no parent, for endpoints that check the parent only when it is set.
     */
    private static void parentWhenSet(Resource resource, ResourceAction... actions) {
        ResourceObjects objects = TABLE.get(resource);
        OnAncestor parentDetail = new OnAncestor(objects.parent(), ResourceAction.DETAIL);
        OnLinked parentDetailWhenSet = OnLinked
                .ifSet(objects.parent(), objects.parentAttribute(), ResourceAction.DETAIL);
        for (ResourceAction action : actions) {
            objects
                    .actions()
                    .put(action, objects
                            .actions()
                            .get(action)
                            .stream()
                            .map(requirement -> requirement.equals(parentDetail) ? parentDetailWhenSet : requirement)
                            .toList());
        }
        if (List.of(actions).contains(ResourceAction.DETAIL)) {
            TABLE
                    .put(resource,
                            new ResourceObjects(objects.entity(), objects.parent(), objects.parentAttribute(),
                                    objects.listing(), objects.actions().get(ResourceAction.DETAIL), objects.actions(),
                                    objects.admitted()));
        }
    }

    /** The object is viewable through a lookup checking only detail on it, such as the resource object lookup. */
    private static void viewedThroughObjectDetail(Resource resource) {
        ResourceObjects objects = TABLE.get(resource);
        TABLE
                .put(resource,
                        new ResourceObjects(objects.entity(), objects.parent(), objects.parentAttribute(),
                                objects.listing(), List.of(new OnObject(ResourceAction.DETAIL)), objects.actions(),
                                objects.admitted()));
    }

    private static void admit(Resource resource, String attribute, Object... values) {
        ResourceObjects objects = TABLE.get(resource);
        TABLE
                .put(resource, new ResourceObjects(objects.entity(), objects.parent(), objects.parentAttribute(),
                        objects.listing(), objects.viewing(), objects.actions(), Map.of(attribute, Set.of(values))));
    }

    private static void onResource(Resource resource, Class<?> entity, ResourceAction... actions) {
        register(resource, entity, Resource.NONE, null, actions, action -> List.of(new OnResource(action)));
    }

    private static void underParent(Resource resource, Class<?> entity, Resource parent, String parentAttribute,
            ResourceAction... actions) {
        register(resource, entity, parent, parentAttribute, actions,
                action -> List.of(new OnObject(action), new OnAncestor(parent, ResourceAction.DETAIL)));
    }

    /** The object is viewable through its detail requirement as registered, before {@link #also} adds to it. */
    private static void register(Resource resource, Class<?> entity, Resource parent, String parentAttribute,
            ResourceAction[] actions, Function<ResourceAction, List<Requirement>> requirements) {
        Map<ResourceAction, List<Requirement>> byAction = new LinkedHashMap<>();
        for (ResourceAction action : actions) {
            byAction.put(action, requirements.apply(action));
        }
        TABLE
                .put(resource, new ResourceObjects(entity, parent, parentAttribute, LISTED,
                        requirements.apply(ResourceAction.DETAIL), byAction, Map.of()));
    }
}

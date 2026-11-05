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
    public sealed interface Requirement permits OnObject, OnResource, OnAncestor, OnLinked {
    }

    /** The action on the object itself, where ownership, object grants and group-members access apply. */
    public record OnObject(ResourceAction action) implements Requirement {
    }

    /** The action on the resource as a whole, for endpoints that take the object's UUID without checking it. */
    public record OnResource(ResourceAction action) implements Requirement {
    }

    /** The action on an ancestor of the object, such as the authority of an RA profile; refused when it has none. */
    public record OnAncestor(Resource ancestor, ResourceAction action) implements Requirement {
    }

    /**
     * The action on the object whose UUID the entity attribute holds, such as a key's token; met when the attribute is
     * empty, since the endpoints check it in code only when it is set.
     */
    public record OnLinked(Resource resource, String attribute, ResourceAction action) implements Requirement {
    }

    /**
     * How the objects of one resource are stored and what each reported action requires.
     *
     * @param entity entity holding the objects, used to tell whether an object exists
     * @param parent resource of the object's parent, or {@link Resource#NONE}
     * @param parentAttribute entity attribute holding the parent's UUID, or {@code null} without a parent
     */
    public record ResourceObjects(Class<?> entity, Resource parent, String parentAttribute,
            Map<ResourceAction, List<Requirement>> actions) {
    }

    private static final Map<Resource, ResourceObjects> TABLE = new EnumMap<>(Resource.class);

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
        onObject(Resource.GROUP, Group.class, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE);
        onObject(Resource.COMPLIANCE_PROFILE, ComplianceProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        onObject(Resource.ENTITY, EntityInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        underParent(Resource.LOCATION, Location.class, Resource.ENTITY, "entityInstanceReferenceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.TOKEN, TokenInstanceReference.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ACTIVATE);
        underParent(Resource.TOKEN_PROFILE, TokenProfile.class, Resource.TOKEN, "tokenInstanceReferenceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        onResource(Resource.VAULT, VaultInstance.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE);
        underParent(Resource.VAULT_PROFILE, VaultProfile.class, Resource.VAULT, "vaultInstanceUuid",
                ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE);
        // Every secret endpoint loads the secret through a check of members on its source vault profile.
        OnLinked sourceVaultProfileMembers = new OnLinked(Resource.VAULT_PROFILE, "sourceVaultProfileUuid",
                ResourceAction.MEMBERS);
        register(Resource.SECRET, Secret.class, Resource.NONE, null,
                new ResourceAction[]{
                        ResourceAction.DETAIL,
                        ResourceAction.UPDATE,
                        ResourceAction.DELETE,
                        ResourceAction.ENABLE,
                        ResourceAction.GET_SECRET_CONTENT},
                action -> List.of(new OnResource(action), sourceVaultProfileMembers));
        onObject(Resource.SIGNING_PROFILE, SigningProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        onObject(Resource.TIME_QUALITY_CONFIGURATION, TimeQualityConfiguration.class, ResourceAction.DETAIL,
                ResourceAction.UPDATE, ResourceAction.DELETE);
        onObject(Resource.TSP_PROFILE, TspProfile.class, ResourceAction.DETAIL, ResourceAction.UPDATE,
                ResourceAction.DELETE, ResourceAction.ENABLE);
        underParent(Resource.TSP_PROFILE_BASIC_CREDENTIAL, TspProfileBasicCredential.class, Resource.TSP_PROFILE,
                "tspProfileUuid", ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE);

        // Renew, rekey and revoke check the certificate resource, and the RA profile and its authority they run under.
        Map<ResourceAction, List<Requirement>> certificate = new LinkedHashMap<>();
        for (ResourceAction action : List
                .of(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ARCHIVE)) {
            certificate.put(action, List.of(new OnObject(action)));
        }
        for (ResourceAction action : List.of(ResourceAction.RENEW, ResourceAction.REVOKE)) {
            certificate
                    .put(action, List
                            .of(new OnResource(action), new OnAncestor(Resource.RA_PROFILE, ResourceAction.DETAIL),
                                    new OnAncestor(Resource.AUTHORITY, ResourceAction.DETAIL)));
        }
        TABLE
                .put(Resource.CERTIFICATE,
                        new ResourceObjects(Certificate.class, Resource.RA_PROFILE, "raProfileUuid", certificate));

        // Key detail includes the event history, and key update the compromise and usage endpoints, which check only
        // the resource. The key endpoints also check the key's token in code, and export its token profile; the
        // operations with a key run through its token profile and check the token.
        OnLinked tokenDetail = new OnLinked(Resource.TOKEN, "tokenInstanceReferenceUuid", ResourceAction.DETAIL);
        OnLinked tokenMembers = new OnLinked(Resource.TOKEN, "tokenInstanceReferenceUuid", ResourceAction.MEMBERS);
        OnLinked tokenProfileDetail = new OnLinked(Resource.TOKEN_PROFILE, "tokenProfileUuid", ResourceAction.DETAIL);
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
        for (ResourceAction action : List
                .of(ResourceAction.ENCRYPT, ResourceAction.DECRYPT, ResourceAction.SIGN, ResourceAction.VERIFY)) {
            key.put(action, List.of(new OnResource(action), new OnAncestor(Resource.TOKEN, ResourceAction.DETAIL)));
        }
        TABLE
                .put(Resource.CRYPTOGRAPHIC_KEY,
                        new ResourceObjects(CryptographicKey.class, Resource.TOKEN, "tokenInstanceReferenceUuid", key));
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
        TABLE.put(resource, new ResourceObjects(entity, parent, parentAttribute, byAction));
    }
}

package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.exception.DanglingReferenceException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The resolution both modes share: nesting, the depth cap, loops, and refusals that name the reference. */
class ReferenceTraversalTest {

    private static final UUID AUTHORITY = UUID.fromString("a0000000-0000-4000-8000-000000000001");
    private static final UUID SECOND_AUTHORITY = UUID.fromString("a0000000-0000-4000-8000-000000000002");
    private static final UUID SECRET = UUID.fromString("5e000000-0000-4000-8000-000000000001");
    private static final UUID CREDENTIAL = UUID.fromString("c0000000-0000-4000-8000-000000000001");

    private final FakeLoader loader = new FakeLoader();

    // ── Nesting ───────────────────────────────────────────────────────────────

    @Nested
    class Nesting {

        @Test
        void resolvesTheSecretOfAReferencedAuthority() throws Exception {
            // given
            loader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("OAuth client", secret(SECRET))));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            lendingEverything().resolve("authority", request);

            // then
            ResourceObjectContentData nested = nestedData(request.getFirst().getData(), 0);
            assertThat(nested)
                    .isInstanceOfSatisfying(ResourceSecretContentData.class,
                            secret -> assertThat(secret.getContent()).isNotNull());
        }

        @Test
        void loadsASharedSecretOnce_whenTwoAuthoritiesReferenceIt() throws Exception {
            // given
            loader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "first",
                            attribute("OAuth client", secret(SECRET))));
            loader
                    .object(AttributeResource.AUTHORITY, SECOND_AUTHORITY, () -> object(AttributeResource.AUTHORITY,
                            "second", attribute("OAuth client", secret(SECRET))));
            List<ResourceObjectContent> multiSelect = references(reference(AttributeResource.AUTHORITY, AUTHORITY),
                    reference(AttributeResource.AUTHORITY, SECOND_AUTHORITY));

            // when
            lendingEverything().resolve("authorities", multiSelect);

            // then
            assertThat(loader.loads(AttributeResource.SECRET, SECRET)).isEqualTo(1);
            assertThat(nestedData(multiSelect.get(1).getData(), 0))
                    .isSameAs(nestedData(multiSelect.get(0).getData(), 0))
                    .isInstanceOf(ResourceSecretContentData.class);
        }

        @Test
        void keepsObjectsOfTwoKindsApart_whenTheyShareAUuid() throws Exception {
            // given
            UUID sharedUuid = UUID.randomUUID();
            loader.object(AttributeResource.AUTHORITY, sharedUuid, () -> object(AttributeResource.AUTHORITY, "a"));
            loader.object(AttributeResource.CREDENTIAL, sharedUuid, () -> object(AttributeResource.CREDENTIAL, "c"));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, sharedUuid),
                    reference(AttributeResource.CREDENTIAL, sharedUuid));

            // when
            lendingEverything().resolve("objects", request);

            // then
            assertThat(request)
                    .extracting(content -> content.getData().getResource())
                    .containsExactly(AttributeResource.AUTHORITY, AttributeResource.CREDENTIAL);
            assertThat(loader.totalLoads()).isEqualTo(2);
        }

        @Test
        void leavesAReferenceAsItIs_whenItsKindHasNoLoader() throws Exception {
            // given
            loader.sentBare(AttributeResource.CERTIFICATE);
            ResourceObjectContent bare = reference(AttributeResource.CERTIFICATE, UUID.randomUUID());
            ResourceObjectContentData original = bare.getData();

            // when
            lendingEverything().resolve("trust", references(bare));

            // then
            assertThat(bare.getData()).isSameAs(original);
        }

        @Test
        void resolvesInsideObjectsLoadedAlready_whenSystemModeLoadedTheRequestsOwn() throws Exception {
            // given
            loader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            ResourceSimpleContentData loadedAuthority = object(AttributeResource.AUTHORITY, "otpki",
                    attribute("OAuth client", secret(SECRET)));
            loadedAuthority.setUuid(AUTHORITY.toString());
            List<ResourceObjectContent> request = references(new ResourceObjectContent("otpki", loadedAuthority));

            // when
            lendingEverything().resolveInsideLoaded(request);

            // then
            assertThat(nestedData(loadedAuthority, 0)).isInstanceOf(ResourceSecretContentData.class);
            assertThat(loader.loads(AttributeResource.AUTHORITY, AUTHORITY)).isZero();
        }

        @Test
        void throwsAttributeException_whenAReferenceUuidIsMalformed() {
            // given
            ResourceSimpleContentData malformed = new ResourceSimpleContentData(AttributeResource.CREDENTIAL);
            malformed.setUuid("not-a-uuid");
            List<ResourceObjectContent> request = references(new ResourceObjectContent(null, malformed));

            // when
            ThrowingCallable resolve = () -> lendingEverything().resolve("credential", request);

            // then
            assertThatThrownBy(resolve).isInstanceOf(AttributeException.class).hasMessageContaining("not-a-uuid");
        }
    }

    // ── Lending ───────────────────────────────────────────────────────────────

    @Nested
    class Lending {

        @Test
        void leavesTheReferencesInsideAnObjectAlone_whenItLendsNothing() throws Exception {
            // given
            loader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("OAuth client", secret(SECRET))));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            new ReferenceTraversal(loader, ReferenceLending.NOTHING).resolve("authority", request);

            // then
            assertThat(nestedData(request.getFirst().getData(), 0))
                    .isInstanceOfSatisfying(ResourceSecretContentData.class,
                            secret -> assertThat(secret.getContent()).isNull());
            assertThat(loader.loads(AttributeResource.SECRET, SECRET)).isZero();
        }

        @Test
        void resolvesWhatAnObjectNestsWithTheLoaderItLends_notWithTheRequestsLoader() throws Exception {
            // given
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("OAuth client", secret(SECRET))));
            FakeLoader lentLoader = new FakeLoader();
            lentLoader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            ReferenceLending lendingTheAuthority = (kind,
                    uuid) -> kind == AttributeResource.AUTHORITY ? lentLoader : null;
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            new ReferenceTraversal(loader, lendingTheAuthority).resolve("authority", request);

            // then
            assertThat(lentLoader.loads(AttributeResource.SECRET, SECRET)).isEqualTo(1);
            assertThat(loader.loads(AttributeResource.SECRET, SECRET)).isZero();
        }

        @Test
        void keepsTheReferencesInsideANestedObjectBare_whenTheLendingDeclinesThatObject() throws Exception {
            // given
            loader.object(AttributeResource.SECRET, SECRET, () -> secretContent("other-connectors-secret"));
            loader
                    .object(AttributeResource.AUTHORITY, SECOND_AUTHORITY, () -> object(AttributeResource.AUTHORITY,
                            "of another connector", attribute("OAuth client", secret(SECRET))));
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("issuer", reference(AttributeResource.AUTHORITY, SECOND_AUTHORITY))));
            ReferenceLending lendingOnlyTheFirstAuthority = (kind, uuid) -> AUTHORITY.equals(uuid) ? loader : null;
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            new ReferenceTraversal(loader, lendingOnlyTheFirstAuthority).resolve("authority", request);

            // then
            ResourceObjectContentData otherAuthority = nestedData(request.getFirst().getData(), 0);
            assertThat(nestedData(otherAuthority, 0))
                    .isInstanceOfSatisfying(ResourceSecretContentData.class,
                            secret -> assertThat(secret.getContent()).isNull());
            assertThat(loader.loads(AttributeResource.SECRET, SECRET)).isZero();
        }

        @Test
        void checksAnObjectTheRequestNames_whenLendingReachedItFirst() throws Exception {
            // given
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("OAuth client", secret(SECRET))));
            loader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            FakeLoader lentLoader = new FakeLoader();
            lentLoader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY),
                    secret(SECRET));

            // when
            lendingTheAuthorityThrough(lentLoader).resolve("objects", request);

            // then
            assertThat(loader.loads(AttributeResource.SECRET, SECRET)).isEqualTo(1);
            assertThat(request.get(1).getData()).isSameAs(nestedData(request.getFirst().getData(), 0));
        }

        @Test
        void refusesAnObjectTheRequestNames_whenOnlyLendingReachedItAndTheCallerMayNotLoadIt() {
            // given
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("OAuth client", secret(SECRET))));
            loader.denied(AttributeResource.SECRET, SECRET);
            FakeLoader lentLoader = new FakeLoader();
            lentLoader.object(AttributeResource.SECRET, SECRET, () -> secretContent("client-secret"));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY),
                    secret(SECRET));

            // when
            ThrowingCallable resolve = () -> lendingTheAuthorityThrough(lentLoader).resolve("objects", request);

            // then
            assertThatThrownBy(resolve)
                    .isInstanceOfSatisfying(ReferenceAccessDeniedException.class,
                            denied -> assertThat(denied.getReference()).isEqualTo("Secret 'oauth-client'"));
        }
    }

    // ── Loops ─────────────────────────────────────────────────────────────────

    @Nested
    class Loops {

        @Test
        void resolvesEachObjectOnceAndEnds_whenTwoObjectsReferenceEachOther() throws Exception {
            // given
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("login", reference(AttributeResource.CREDENTIAL, CREDENTIAL))));
            loader
                    .object(AttributeResource.CREDENTIAL, CREDENTIAL, () -> object(AttributeResource.CREDENTIAL,
                            "login", attribute("owner", reference(AttributeResource.AUTHORITY, AUTHORITY))));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            lendingEverything().resolve("authority", request);

            // then
            ResourceObjectContentData credential = nestedData(request.getFirst().getData(), 0);
            ResourceObjectContentData backReference = nestedData(credential, 0);
            assertThat(loader.loads(AttributeResource.AUTHORITY, AUTHORITY)).isEqualTo(1);
            assertThat(loader.loads(AttributeResource.CREDENTIAL, CREDENTIAL)).isEqualTo(1);
            assertThat(((ResourceSimpleContentData) backReference).getAttributes()).isNull();
        }

        @Test
        void resolvesTheObjectOnce_whenItReferencesItself() throws Exception {
            // given
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "self",
                            attribute("parent", reference(AttributeResource.AUTHORITY, AUTHORITY))));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            lendingEverything().resolve("authority", request);

            // then
            assertThat(loader.loads(AttributeResource.AUTHORITY, AUTHORITY)).isEqualTo(1);
        }
    }

    // ── DepthCap ──────────────────────────────────────────────────────────────

    @Nested
    class DepthCap {

        @Test
        void resolvesAChain_whenItEndsAtTheCap() throws Exception {
            // given
            int longestResolvedChain = ReferenceTraversal.MAX_DEPTH + 1;
            List<ResourceObjectContent> request = references(chainOf(longestResolvedChain));

            // when
            lendingEverything().resolve("chain", request);

            // then
            assertThat(loader.totalLoads()).isEqualTo(longestResolvedChain);
        }

        @Test
        void refusesTheWholeRequestNamingTheReference_whenAChainGoesPastTheCap() {
            // given
            int oneLinkPastTheCap = ReferenceTraversal.MAX_DEPTH + 2;
            List<ResourceObjectContent> request = references(chainOf(oneLinkPastTheCap));

            // when
            ThrowingCallable resolve = () -> lendingEverything().resolve("chain", request);

            // then
            assertThatThrownBy(resolve)
                    .isInstanceOf(ReferenceExpansionException.class)
                    .hasMessageContaining("Credential 'link-%d'".formatted(ReferenceTraversal.MAX_DEPTH + 1))
                    .hasMessageContaining("of Credential 'link-%d'".formatted(ReferenceTraversal.MAX_DEPTH))
                    .hasMessageContaining("more than %d levels deep".formatted(ReferenceTraversal.MAX_DEPTH));
        }
    }

    // ── Refusals ──────────────────────────────────────────────────────────────

    @Nested
    class Refusals {

        @Test
        void keepsTheLoadersWords_whenItNamedTheMissingReferenceItself() {
            // given
            DanglingReferenceException namedByTheLoader = new DanglingReferenceException(
                    "Attribute 'Vault login' refers to Secret 'login', which does not exist. Select another one.");
            ReferenceLoader loaderNamingIt = (kind, uuid) -> {
                throw namedByTheLoader;
            };
            List<ResourceObjectContent> request = references(reference(AttributeResource.SECRET, SECRET));

            // when
            ThrowingCallable resolve = () -> new ReferenceTraversal(loaderNamingIt, ReferenceLending.NOTHING)
                    .resolve("pin", request);

            // then
            assertThatThrownBy(resolve).isSameAs(namedByTheLoader);
        }

        @Test
        void failsClosedNamingTheNestedReference_whenTheLoaderDeniesIt() {
            // given
            loader.denied(AttributeResource.SECRET, SECRET);
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("OAuth client", secret(SECRET))));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            ThrowingCallable resolve = () -> lendingEverything().resolve("authority", request);

            // then
            assertThatThrownBy(resolve)
                    .isInstanceOfSatisfying(ReferenceAccessDeniedException.class,
                            denied -> assertThat(denied.getReference())
                                    .isEqualTo(
                                            "Secret 'oauth-client' in attribute 'OAuth client' of Authority 'otpki'"));
        }

        @Test
        void namesTheAttributeAndItsObject_whenANestedObjectIsGone() {
            // given
            loader
                    .object(AttributeResource.AUTHORITY, AUTHORITY, () -> object(AttributeResource.AUTHORITY, "otpki",
                            attribute("OAuth client", secret(SECRET))));
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            ThrowingCallable resolve = () -> lendingEverything().resolve("authority", request);

            // then
            assertThatThrownBy(resolve)
                    .isInstanceOf(DanglingReferenceException.class)
                    .hasMessage(
                            "Attribute 'OAuth client' of Authority 'otpki' refers to Secret 'oauth-client', which does not "
                                    + "exist. Select another one.");
        }

        @Test
        void namesTheRequestAttribute_whenAReferencedObjectIsGone() {
            // given
            List<ResourceObjectContent> request = references(reference(AttributeResource.AUTHORITY, AUTHORITY));

            // when
            ThrowingCallable resolve = () -> lendingEverything().resolve("authority", request);

            // then
            assertThatThrownBy(resolve)
                    .isInstanceOf(DanglingReferenceException.class)
                    .hasMessageStartingWith("Attribute 'authority' refers to Authority");
        }
    }

    @Test
    void keysAnObjectByItsKindAndUuid() {
        // given
        UUID sharedUuid = UUID.randomUUID();

        // when
        String authorityKey = ReferenceTraversal.key(AttributeResource.AUTHORITY, sharedUuid);

        // then
        assertThat(authorityKey)
                .isNotEqualTo(ReferenceTraversal.key(AttributeResource.CREDENTIAL, sharedUuid))
                .contains(sharedUuid.toString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** A traversal whose every object lends what it nests, through the same fake loader. */
    private ReferenceTraversal lendingEverything() {
        return new ReferenceTraversal(loader, (kind, uuid) -> loader);
    }

    /** A traversal in which only authorities lend what they nest, through the given loader. */
    private ReferenceTraversal lendingTheAuthorityThrough(ReferenceLoader lentLoader) {
        return new ReferenceTraversal(loader, (kind, uuid) -> kind == AttributeResource.AUTHORITY ? lentLoader : null);
    }

    /**
     * A chain of credentials, each referencing the next, registered with the loader. Returns the reference to the
     * first, which the request carries.
     */
    private ResourceObjectContent chainOf(int length) {
        List<UUID> links = new ArrayList<>();
        for (int i = 0; i < length; i++) {
            links.add(UUID.randomUUID());
        }
        for (int i = 0; i < length; i++) {
            String name = "link-" + i;
            ResponseAttribute[] next = i + 1 < length
                    ? new ResponseAttribute[]{
                            attribute("next",
                                    reference(AttributeResource.CREDENTIAL, links.get(i + 1), "link-" + (i + 1)))}
                    : new ResponseAttribute[0];
            loader
                    .object(AttributeResource.CREDENTIAL, links.get(i),
                            () -> object(AttributeResource.CREDENTIAL, name, copyOf(next)));
        }
        return reference(AttributeResource.CREDENTIAL, links.getFirst(), "link-0");
    }

    /** Fresh reference wrappers, since resolution replaces the data of the wrapper it walks. */
    private static ResponseAttribute[] copyOf(ResponseAttribute[] attributes) {
        ResponseAttribute[] copies = new ResponseAttribute[attributes.length];
        for (int i = 0; i < attributes.length; i++) {
            ResponseAttributeV3 original = (ResponseAttributeV3) attributes[i];
            ResourceObjectContent reference = (ResourceObjectContent) original.getContent().getFirst();
            copies[i] = attribute(original.getLabel(),
                    new ResourceObjectContent(reference.getReference(), reference.getData()));
        }
        return copies;
    }

    private static List<ResourceObjectContent> references(ResourceObjectContent... references) {
        return new ArrayList<>(List.of(references));
    }

    private static ResourceObjectContent reference(AttributeResource kind, UUID uuid) {
        return reference(kind, uuid, kind.name().toLowerCase() + "-ref");
    }

    private static ResourceObjectContent reference(AttributeResource kind, UUID uuid, String name) {
        ResourceSimpleContentData data = new ResourceSimpleContentData(kind);
        data.setUuid(uuid.toString());
        data.setName(name);
        return new ResourceObjectContent(name, data);
    }

    private static ResourceObjectContent secret(UUID uuid) {
        return new ResourceObjectContent("oauth-client",
                new ResourceSecretContentData(uuid.toString(), "oauth-client", null));
    }

    private static ResourceSecretContentData secretContent(String password) {
        BasicAuthSecretContent content = new BasicAuthSecretContent();
        content.setUsername("client");
        content.setPassword(password);
        ResourceSecretContentData data = new ResourceSecretContentData();
        data.setContent(content);
        return data;
    }

    private static ResourceSimpleContentData object(AttributeResource kind, String name,
            ResponseAttribute... attributes) {
        ResourceSimpleContentData data = new ResourceSimpleContentData(kind);
        data.setName(name);
        data.setAttributes(new ArrayList<>(List.of(attributes)));
        return data;
    }

    private static ResponseAttribute attribute(String label, ResourceObjectContent reference) {
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        content.add(reference);
        return new ResponseAttributeV3(content, UUID.randomUUID(), label.replace(' ', '_'), label, AttributeType.DATA,
                AttributeContentType.RESOURCE, AttributeVersion.V3);
    }

    private static ResourceObjectContentData nestedData(ResourceObjectContentData object, int attributeIndex) {
        ResponseAttribute attribute = ((ResourceSimpleContentData) object).getAttributes().get(attributeIndex);
        List<?> content = attribute.getContent();
        return ((ResourceObjectContent) content.getFirst()).getData();
    }

    /**
     * Loads registered objects afresh on every call and counts the calls. An unregistered object is not found, and a
     * kind a test sends bare has no content.
     */
    private static final class FakeLoader implements ReferenceLoader {

        private final Map<String, Supplier<ResourceObjectContentData>> objects = new HashMap<>();
        private final Map<String, Integer> loads = new HashMap<>();
        private final List<String> denied = new ArrayList<>();
        private final Set<AttributeResource> bareKinds = EnumSet.noneOf(AttributeResource.class);

        void object(AttributeResource kind, UUID uuid, Supplier<ResourceObjectContentData> content) {
            objects.put(ReferenceTraversal.key(kind, uuid), content);
        }

        void sentBare(AttributeResource kind) {
            bareKinds.add(kind);
        }

        void denied(AttributeResource kind, UUID uuid) {
            denied.add(ReferenceTraversal.key(kind, uuid));
        }

        int loads(AttributeResource kind, UUID uuid) {
            return loads.getOrDefault(ReferenceTraversal.key(kind, uuid), 0);
        }

        int totalLoads() {
            return loads.values().stream().mapToInt(Integer::intValue).sum();
        }

        @Override
        public ResourceObjectContentData load(AttributeResource kind, UUID uuid) throws NotFoundException {
            String key = ReferenceTraversal.key(kind, uuid);
            if (bareKinds.contains(kind)) {
                return null;
            }
            if (denied.contains(key)) {
                throw new AccessDeniedException("denied");
            }
            Supplier<ResourceObjectContentData> content = objects.get(key);
            if (content == null) {
                throw new NotFoundException(kind.getLabel(), uuid.toString());
            }
            loads.merge(key, 1, Integer::sum);
            return content.get();
        }
    }
}

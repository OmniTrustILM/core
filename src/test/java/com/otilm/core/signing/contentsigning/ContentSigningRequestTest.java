package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContentSigningRequestTest {

    private static final byte[] DOCUMENT = "a document".getBytes();

    private static final byte[] SHA512_DIGEST = new byte[64];

    @Test
    void returnsTheIdentifiersInRequestOrder() {
        // given
        List<ContentSigningItem> items = List.of(itemNamed("second"), itemNamed("first"));

        // when
        List<String> identifiers = inlineRequestOf(items).identifiers();

        // then
        assertThat(identifiers).containsExactly("second", "first");
    }

    @Test
    void refusesAnEmptyBatch() {
        // given
        List<ContentSigningItem> noItems = List.of();

        // when
        ThrowingCallable create = () -> inlineRequestOf(noItems);

        // then
        assertThatThrownBy(create).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("no document");
    }

    @Test
    void sendsTheDocumentItself_whenTheBatchTravelsInline() {
        // given
        ContentSigningItem item = itemNamed("first");

        // when
        DocumentTransferDto transfer = inlineRequestOf(List.of(item)).transferOf(item);

        // then
        assertThat(transfer).isEqualTo(new InlineDocumentTransferDto(DOCUMENT));
    }

    @Test
    void sendsTheDigestUnderTheBatchAlgorithm_whenTheBatchTravelsAsDigests() {
        // given
        var item = new ContentSigningItem("first", SHA512_DIGEST, SHA512_DIGEST);
        var request = new ContentSigningRequest(DocumentTransferMode.DIGEST_ONLY, DigestAlgorithm.SHA_512,
                List.of(item), List.of());

        // when
        DocumentTransferDto transfer = request.transferOf(item);

        // then
        assertThat(transfer).isEqualTo(new DigestOnlyDocumentTransferDto(SHA512_DIGEST, DigestAlgorithm.SHA_512));
    }

    @Test
    void returnsTheAuthorizedDigestUnderTheBatchAlgorithm_whenTheBatchUsesSha512() {
        // given
        var item = new ContentSigningItem("first", DOCUMENT, SHA512_DIGEST);
        var request = new ContentSigningRequest(DocumentTransferMode.INLINE, DigestAlgorithm.SHA_512, List.of(item),
                List.of());

        // when
        DocumentDigest authorized = request.authorizedDigestOf(item);

        // then
        assertThat(authorized).isEqualTo(new DocumentDigest(DigestAlgorithm.SHA_512, SHA512_DIGEST));
    }

    @Test
    void bindsNoAuthorizedDigests_whenNoItemCarriesOne() {
        // given
        var item = ContentSigningItem.withoutAuthorizedDigest("first", DOCUMENT);

        // when
        var request = new ContentSigningRequest(DocumentTransferMode.INLINE, null, List.of(item), List.of());

        // then
        assertThat(request.bindsAuthorizedDigests()).isFalse();
    }

    @Test
    void bindsAuthorizedDigests_whenEveryItemCarriesOne() {
        // given
        List<ContentSigningItem> items = List.of(itemNamed("first"), itemNamed("second"));

        // when
        ContentSigningRequest request = inlineRequestOf(items);

        // then
        assertThat(request.bindsAuthorizedDigests()).isTrue();
    }

    @Test
    void refusesABatch_whenOnlyALaterItemCarriesAnAuthorizedDigest() {
        // given
        List<ContentSigningItem> items = List
                .of(ContentSigningItem.withoutAuthorizedDigest("first", DOCUMENT), itemNamed("second"));

        // when
        ThrowingCallable create = () -> inlineRequestOf(items);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("every document or none");
    }

    @Test
    void refusesABatch_whenOnlyTheFirstItemCarriesAnAuthorizedDigest() {
        // given
        List<ContentSigningItem> items = List
                .of(itemNamed("first"), ContentSigningItem.withoutAuthorizedDigest("second", DOCUMENT));

        // when
        ThrowingCallable create = () -> inlineRequestOf(items);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("every document or none");
    }

    @Test
    void refusesABatchNamingNoDigestAlgorithm_whenItTravelsAsDigests() {
        // given
        var item = ContentSigningItem.withoutAuthorizedDigest("first", SHA512_DIGEST);

        // when
        ThrowingCallable create = () -> new ContentSigningRequest(DocumentTransferMode.DIGEST_ONLY, null, List.of(item),
                List.of());

        // then
        assertThatThrownBy(create).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("digestAlgorithm");
    }

    @Test
    void refusesABatchNamingNoDigestAlgorithm_whenItsItemsCarryAuthorizedDigests() {
        // given
        List<ContentSigningItem> items = List.of(itemNamed("first"));

        // when
        ThrowingCallable create = () -> new ContentSigningRequest(DocumentTransferMode.INLINE, null, items, List.of());

        // then
        assertThatThrownBy(create).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("digestAlgorithm");
    }

    @Test
    void refusesABatchNamingADigestAlgorithm_whenItCarriesNoDigests() {
        // given
        var item = ContentSigningItem.withoutAuthorizedDigest("first", DOCUMENT);

        // when
        ThrowingCallable create = () -> new ContentSigningRequest(DocumentTransferMode.INLINE, DigestAlgorithm.SHA_256,
                List.of(item), List.of());

        // then
        assertThatThrownBy(create).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("digestAlgorithm");
    }

    @Test
    void refusesToReturnAnAuthorizedDigest_whenTheBatchBindsNone() {
        // given
        var item = ContentSigningItem.withoutAuthorizedDigest("first", DOCUMENT);
        var request = new ContentSigningRequest(DocumentTransferMode.INLINE, null, List.of(item), List.of());

        // when
        ThrowingCallable authorizedDigest = () -> request.authorizedDigestOf(item);

        // then
        assertThatThrownBy(authorizedDigest).isInstanceOf(IllegalStateException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ContentSigningRequest inlineRequestOf(List<ContentSigningItem> items) {
        return new ContentSigningRequest(DocumentTransferMode.INLINE, DigestAlgorithm.SHA_256, items, List.of());
    }

    private static ContentSigningItem itemNamed(String identifier) {
        return new ContentSigningItem(identifier, DOCUMENT, new byte[32]);
    }
}

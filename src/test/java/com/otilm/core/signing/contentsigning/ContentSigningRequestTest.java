package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.common.signature.SignatureLevel;
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
        var request = new ContentSigningRequest(SignatureLevel.SIGNED, DocumentTransferMode.DIGEST_ONLY,
                DigestAlgorithm.SHA_512, List.of(item), null);

        // when
        DocumentTransferDto transfer = request.transferOf(item);

        // then
        assertThat(transfer).isEqualTo(new DigestOnlyDocumentTransferDto(SHA512_DIGEST, DigestAlgorithm.SHA_512));
    }

    @Test
    void returnsTheAuthorizedDigestUnderTheBatchAlgorithm() {
        // given
        var item = new ContentSigningItem("first", DOCUMENT, SHA512_DIGEST);
        var request = new ContentSigningRequest(SignatureLevel.SIGNED, DocumentTransferMode.INLINE,
                DigestAlgorithm.SHA_512, List.of(item), null);

        // when
        DocumentDigest authorized = request.authorizedDigestOf(item);

        // then
        assertThat(authorized).isEqualTo(new DocumentDigest(DigestAlgorithm.SHA_512, SHA512_DIGEST));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ContentSigningRequest inlineRequestOf(List<ContentSigningItem> items) {
        return new ContentSigningRequest(SignatureLevel.SIGNED, DocumentTransferMode.INLINE, DigestAlgorithm.SHA_256,
                items, null);
    }

    private static ContentSigningItem itemNamed(String identifier) {
        return new ContentSigningItem(identifier, DOCUMENT, new byte[32]);
    }
}

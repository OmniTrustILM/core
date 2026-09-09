package com.otilm.core.cbom.client;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LinkHeaderTest {

    private static final String NEXT = "<bom?cursor=djF8MTc4ODQ1MTIwMDAwMHx1cm4&limit=1000>; rel=\"next\"";

    @Test
    void returnsTheTargetOfTheNextLink() {
        assertThat(LinkHeader.nextTarget(List.of(NEXT))).contains("bom?cursor=djF8MTc4ODQ1MTIwMDAwMHx1cm4&limit=1000");
    }

    @Test
    void acceptsABareRelValueAndIgnoresCase() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>;rel=Next"))).contains("bom?cursor=a&limit=5");
    }

    @Test
    void findsNextAmongSeveralLinksInOneHeaderLine() {
        String header = "<bom?cursor=first&limit=5>; rel=\"prev\", <bom?cursor=second&limit=5>; rel=\"next\"";
        assertThat(LinkHeader.nextTarget(List.of(header))).contains("bom?cursor=second&limit=5");
    }

    @Test
    void findsNextAmongSeveralHeaderLines() {
        assertThat(LinkHeader.nextTarget(List.of("<x>; rel=\"self\"", NEXT)))
                .contains("bom?cursor=djF8MTc4ODQ1MTIwMDAwMHx1cm4&limit=1000");
    }

    @Test
    void matchesNextInsideASpaceSeparatedRelList() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=\"alternate next\"")))
                .contains("bom?cursor=a&limit=5");
    }

    @Test
    void aCommaInsideAQuotedParameterDoesNotSplitTheLink() {
        String header = "<bom?cursor=a&limit=5>; title=\"a, b; c\"; rel=\"next\"";
        assertThat(LinkHeader.nextTarget(List.of(header))).contains("bom?cursor=a&limit=5");
    }

    @Test
    void ignoresLinksWithOtherRelations() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=\"prev\""))).isEmpty();
    }

    @Test
    void relNextIsNotMatchedAsASubstring() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=\"nextish\""))).isEmpty();
    }

    @Test
    void emptyOrMissingHeadersYieldNothing() {
        assertThat(LinkHeader.nextTarget(null)).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of())).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of(""))).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of("garbage without brackets; rel=\"next\""))).isEmpty();
    }

    @Test
    void aLongHeaderIsWalkedWithoutRecursion() {
        // The grammar this parses needs repetition over an alternation, which a backtracking regex engine recurses
        // on -- one frame per repetition, so a header this size overflows the stack. The scanner must not.
        String title = "x".repeat(200_000);
        String parameters = "; anchor=\"#a\"".repeat(50_000);
        String header = "<bom?cursor=a&limit=5>; title=\"" + title + "\"" + parameters + "; rel=\"prev\", "
                + "<bom?cursor=b&limit=5>; rel=\"next\"";
        assertThat(LinkHeader.nextTarget(List.of(header))).contains("bom?cursor=b&limit=5");
    }

    @Test
    void anEscapedQuoteDoesNotEndAQuotedValue() {
        String header = "<bom?cursor=a&limit=5>; title=\"a \\\" ; b\"; rel=\"next\"";
        assertThat(LinkHeader.nextTarget(List.of(header))).contains("bom?cursor=a&limit=5");
    }

    @Test
    void aTargetInsideAQuotedValueIsNotReadAsALink() {
        String header = "<bom?cursor=a&limit=5>; title=\"<bom?cursor=trap&limit=5>; rel=next\"; rel=\"prev\", "
                + "<bom?cursor=b&limit=5>; rel=\"next\"";
        assertThat(LinkHeader.nextTarget(List.of(header))).contains("bom?cursor=b&limit=5");
    }

    @Test
    void theFirstRelOfALinkDecidesIt() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=\"prev\"; rel=\"next\""))).isEmpty();
    }

    @Test
    void aRelWithoutAValueRelatesToNothing() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel; rel=\"next\""))).isEmpty();
    }

    @Test
    void aParameterWithoutAValueDoesNotHideTheRel() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; anchor; rel=\"next\"")))
                .contains("bom?cursor=a&limit=5");
    }

    @Test
    void textThatIsNotAParameterListEndsTheLink() {
        String header = "<bom?cursor=a&limit=5>; rel=\"prev\" &&, <bom?cursor=b&limit=5>; rel=\"next\"";
        assertThat(LinkHeader.nextTarget(List.of(header))).contains("bom?cursor=b&limit=5");
    }

    @Test
    void anUnterminatedTargetOrQuotedValueYieldsNothing() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5; rel=\"next\""))).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; title=\"oops"))).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; title=\"oops\\"))).isEmpty();
    }

    @Test
    void aNullHeaderValueDoesNotStopTheSearch() {
        assertThat(LinkHeader.nextTarget(Arrays.asList(null, NEXT)))
                .contains("bom?cursor=djF8MTc4ODQ1MTIwMDAwMHx1cm4&limit=1000");
    }

    @Test
    void anUnquotedValueEndsAtTheNextParameterLinkOrSpace() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=next; title=x")))
                .contains("bom?cursor=a&limit=5");
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=prev, <bom?cursor=b&limit=5>; rel=next")))
                .contains("bom?cursor=b&limit=5");
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=next junk")))
                .contains("bom?cursor=a&limit=5");
    }

    @Test
    void aParameterNameMayHoldAnyTokenCharacter() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; X-Meta9!=\"v\"; rel=\"next\"")))
                .contains("bom?cursor=a&limit=5");
    }

    @Test
    void aHeaderThatEndsMidParameterYieldsNothing() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>"))).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>;"))).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel"))).isEmpty();
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel="))).isEmpty();
    }

    @Test
    void aRelListMayBePaddedWithSpaces() {
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=\" next \"")))
                .contains("bom?cursor=a&limit=5");
        assertThat(LinkHeader.nextTarget(List.of("<bom?cursor=a&limit=5>; rel=\"prev \""))).isEmpty();
    }
}

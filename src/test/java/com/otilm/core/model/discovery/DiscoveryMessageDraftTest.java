package com.otilm.core.model.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The draft refuses what the message table cannot store, so a producer's mistake fails where it was made. Why that
 * matters is on {@link DiscoveryMessageDraft} itself.
 */
class DiscoveryMessageDraftTest {

    @Test
    void aCodeThatNamesNothingIsRefused() {
        for (String noCode : new String[]{null, "", "   "}) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING, noCode, "text", 1))
                    .withMessageContaining("code");
        }
    }

    @Test
    void textNobodyCouldReadIsRefused() {
        for (String noText : new String[]{null, "", "   "}) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING, "aCode", noText, 1))
                    .withMessageContaining("text");
        }
    }

    @Test
    void aProblemThatHappenedNoTimesIsRefused() {
        // A message exists because something happened, so a count below one describes nothing the log can hold.
        for (long never : new long[]{0, -1}) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> new DiscoveryMessageDraft(DiscoveryMessageSeverity.INFO, "aCode", "text", never))
                    .withMessageContaining("occurrence");
        }
    }

    @Test
    void aDraftNamingAKindOfProblemIsAccepted() {
        assertThatCode(() -> new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING,
                DiscoveryMessageCode.INVENTORY_GAP, "A discovered certificate could not be imported.", 12))
                .doesNotThrowAnyException();
    }
}

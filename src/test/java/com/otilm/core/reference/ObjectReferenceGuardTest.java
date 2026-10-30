package com.otilm.core.reference;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ObjectReferenceGuardTest {

    @Test
    void namesEveryReferrer_whenTheCallerMaySeeThemAll() {
        // given
        var tokenUse = "Token 'a' (attribute 'PIN')";
        var acmeUse = "ACME Profile 'b' (key)";

        // when
        String usedBy = ObjectReferenceGuard.usedBy(List.of(tokenUse, acmeUse), 0);

        // then
        assertThat(usedBy).isEqualTo(tokenUse + "; " + acmeUse);
    }

    @Test
    void countsAHiddenReferrer_afterTheVisibleOnes() {
        // given
        var tokenUse = "Token 'a' (attribute 'PIN')";

        // when
        String usedBy = ObjectReferenceGuard.usedBy(List.of(tokenUse), 1);

        // then
        assertThat(usedBy).isEqualTo(tokenUse + "; 1 object you are not allowed to see");
    }

    @Test
    void countsHiddenReferrersAlone_whenNoneIsVisible() {
        // given
        var hiddenCount = 3;

        // when
        String usedBy = ObjectReferenceGuard.usedBy(List.of(), hiddenCount);

        // then
        assertThat(usedBy).isEqualTo(hiddenCount + " objects you are not allowed to see");
    }
}

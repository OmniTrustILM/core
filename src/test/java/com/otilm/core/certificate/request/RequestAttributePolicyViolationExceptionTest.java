package com.otilm.core.certificate.request;

import com.otilm.api.exception.ValidationException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RequestAttributePolicyViolationExceptionTest {

    @Test
    void carriesMessageAndDetails_asValidationException() {
        // given — a policy message and a single detail
        var policyMessage = "policy failed";
        var detail = "missing required RDN: CN";

        // when
        RequestAttributePolicyViolationException ex =
                new RequestAttributePolicyViolationException(policyMessage, List.of(detail));

        // then — a ValidationException whose message is the policy message; the detail is also surfaced via the error list
        assertThat(ex).isInstanceOf(ValidationException.class);
        assertThat(ex.getMessage()).isEqualTo(policyMessage);
        assertThat(ex.getPolicyDetails()).containsExactly(detail);
        assertThat(ex.getErrors()).hasSize(1);
    }

    @Test
    void returnsEmptyDetails_whenConstructedWithNull() {
        // given / when — null details
        RequestAttributePolicyViolationException ex =
                new RequestAttributePolicyViolationException("policy failed", null);

        // then
        assertThat(ex.getPolicyDetails()).isEmpty();
    }
}

package com.otilm.core.service.renewal;

/** A request to change the renewal window of a certificate, named by where it comes from. */
public sealed interface WindowWrite {

    /** The window of the RA profile policy; {@code null} when the policy gives the certificate none. */
    record Policy(Window window) implements WindowWrite {
    }

    /** A window the certificate authority suggested. */
    record Authority(Window window, String explanationUrl) implements WindowWrite {
    }

    /** The certificate authority gives no advice for the certificate. */
    record AuthorityNoAdvice() implements WindowWrite {
    }

    /** A window an administrator forced. */
    record Forced(Window window, String explanationUrl) implements WindowWrite {
    }

    /** The certificate's RA profile was assigned, changed or removed. */
    record RaProfileReset() implements WindowWrite {
    }
}

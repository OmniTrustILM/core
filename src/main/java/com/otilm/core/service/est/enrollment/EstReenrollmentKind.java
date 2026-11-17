package com.otilm.core.service.est.enrollment;

/** What a re-enrolment does to the key of the certificate it replaces. */
public enum EstReenrollmentKind {
    /** The request carries the key of the current certificate. */
    RENEWAL,
    /** The request carries another key. */
    REKEY
}

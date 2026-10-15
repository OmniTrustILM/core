package com.otilm.core.cbom.client;

import com.otilm.api.exception.CbomRepositoryException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

/**
 * The configured CBOM Repository URL answers, but nothing there serves the repository's listing: the opening search
 * came back 404. A deployment without the repository looks exactly like this when its URL points at a shared ingress,
 * so the scheduled passes read it as "no repository" rather than as a failed run.
 */
public class CbomRepositoryNotDeployedException extends CbomRepositoryException {

    public CbomRepositoryNotDeployedException() {
        super(ProblemDetail
                .forStatusAndDetail(HttpStatus.NOT_FOUND,
                        "No CBOM Repository answers at the configured URL (HTTP 404 on its listing)"));
    }
}

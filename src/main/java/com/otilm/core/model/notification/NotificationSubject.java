package com.otilm.core.model.notification;

import com.otilm.api.model.core.auth.Resource;

/**
 * The object inside a notification's target that the notification is about, for events whose subject is not the target
 * itself. {@code parentIdentification} names the object the subject is nested in, when there is one, so the reader can
 * be taken to the subject without first having to look it up: a reply names its thread root.
 */
public record NotificationSubject(Resource type, String identification, String parentIdentification) {
}

package com.otilm.core.service.notifications;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.NotificationDataCategory;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.util.AuthHelper;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Config-time authorization gate for notification data categories. Enabling a gated category routes object data to the
 * profile's connector at send time, when loads run in system context with no user to authorize -- so the configuring
 * user must hold the listed permissions without any object-level restriction at configuration time. OBJECT_CONTENT
 * lists the certificate content exporter's requirements; registering another content exporter requires extending this
 * map as part of that exporter's own design, never silently.
 *
 * <p>
 * Trust boundary: the gate fires on the two edges that change the export decision itself -- enabling a gated category
 * (what data leaves) and moving the profile to another notification instance while a gated category stays enabled
 * (where it leaves to). Recipient edits and notification-instance configuration updates deliberately do not re-fire it:
 * recipients only choose who the provider addresses (holders of NOTIFICATION_PROFILE UPDATE already direct all
 * notification content, including the event payload, to any recipients), and administering an instance's connector
 * configuration is governed by the instance's own update authority, which already controls where every notification
 * through that instance -- enriched or not -- is delivered. The gate is point-in-time: permissions lost later do not
 * retroactively disable existing profiles.
 */
@Component
@AllArgsConstructor
public class NotificationDataCategoryGate {

    private record RequiredPermission(Resource resource, ResourceAction action) {

        String describe() {
            return resource.name() + " " + action.name();
        }
    }

    private static final Map<NotificationDataCategory, List<RequiredPermission>> GATED_CATEGORIES = Map
            .of(NotificationDataCategory.CUSTOM_ATTRIBUTES,
                    List.of(new RequiredPermission(Resource.ATTRIBUTE, ResourceAction.MEMBERS)),
                    NotificationDataCategory.OBJECT_CONTENT,
                    List
                            .of(new RequiredPermission(Resource.CERTIFICATE, ResourceAction.DETAIL),
                                    new RequiredPermission(Resource.RA_PROFILE, ResourceAction.MEMBERS)));

    private final AuthHelper authHelper;

    public static boolean isGated(NotificationDataCategory category) {
        return GATED_CATEGORIES.containsKey(category);
    }

    /**
     * Refuses with an actionable message unless the current user holds every permission the given categories require
     * without allow-list or deny-list restriction.
     */
    public void assertCanEnable(Collection<NotificationDataCategory> categories) {
        for (NotificationDataCategory category : categories) {
            for (RequiredPermission required : GATED_CATEGORIES.getOrDefault(category, List.of())) {
                SecurityResourceFilter filter = authHelper
                        .loadObjectPermissions(required.resource(), required.action());
                if (filter.areOnlySpecificObjectsAllowed() || !filter.getForbiddenObjects().isEmpty()) {
                    throw new ValidationException(ValidationError
                            .create("Enabling notification data category {} requires unrestricted {} access",
                                    category.getLabel(), required.describe()));
                }
            }
        }
    }
}

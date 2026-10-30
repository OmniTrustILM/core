package com.otilm.core.service.notifications;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.NotificationDataCategory;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.util.AuthHelper;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationDataCategoryGateTest {

    private static final SecurityResourceFilter UNRESTRICTED = new SecurityResourceFilter(List.of(), List.of(), false);
    private static final SecurityResourceFilter ALLOW_LISTED = new SecurityResourceFilter(
            List.of(UUID.randomUUID().toString()), List.of(), true);
    private static final SecurityResourceFilter DENY_LISTED = new SecurityResourceFilter(List.of(),
            List.of(UUID.randomUUID().toString()), false);

    @Mock
    private AuthHelper authHelper;

    private NotificationDataCategoryGate gate() {
        return new NotificationDataCategoryGate(authHelper);
    }

    @Test
    void unrestrictedUserEnablesEverything() {
        when(authHelper.loadObjectPermissions(any(), any())).thenReturn(UNRESTRICTED);
        assertDoesNotThrow(() -> gate().assertCanEnable(List.of(NotificationDataCategory.values())));
    }

    @Test
    void allowListRestrictedAttributeMembersRefusesCustomAttributes() {
        when(authHelper.loadObjectPermissions(Resource.ATTRIBUTE, ResourceAction.MEMBERS)).thenReturn(ALLOW_LISTED);

        NotificationDataCategoryGate gate = gate();
        List<NotificationDataCategory> categories = List.of(NotificationDataCategory.CUSTOM_ATTRIBUTES);
        ValidationException ex = assertThrows(ValidationException.class, () -> gate.assertCanEnable(categories));
        assertTrue(ex.getMessage().contains("ATTRIBUTE"), ex.getMessage());
        assertTrue(ex.getMessage().contains("MEMBERS"), ex.getMessage());
    }

    @Test
    void denyListRestrictionAlsoRefuses() {
        when(authHelper.loadObjectPermissions(Resource.ATTRIBUTE, ResourceAction.MEMBERS)).thenReturn(DENY_LISTED);

        NotificationDataCategoryGate gate = gate();
        List<NotificationDataCategory> categories = List.of(NotificationDataCategory.CUSTOM_ATTRIBUTES);
        assertThrows(ValidationException.class, () -> gate.assertCanEnable(categories));
    }

    @Test
    void objectContentRequiresCertificateDetail() {
        when(authHelper.loadObjectPermissions(Resource.CERTIFICATE, ResourceAction.DETAIL)).thenReturn(ALLOW_LISTED);

        NotificationDataCategoryGate gate = gate();
        List<NotificationDataCategory> categories = List.of(NotificationDataCategory.OBJECT_CONTENT);
        ValidationException ex = assertThrows(ValidationException.class, () -> gate.assertCanEnable(categories));
        assertTrue(ex.getMessage().contains("CERTIFICATE"), ex.getMessage());
        assertTrue(ex.getMessage().contains("DETAIL"), ex.getMessage());
    }

    @Test
    void objectContentRequiresRaProfileMembers() {
        when(authHelper.loadObjectPermissions(Resource.CERTIFICATE, ResourceAction.DETAIL)).thenReturn(UNRESTRICTED);
        when(authHelper.loadObjectPermissions(Resource.RA_PROFILE, ResourceAction.MEMBERS)).thenReturn(ALLOW_LISTED);

        NotificationDataCategoryGate gate = gate();
        List<NotificationDataCategory> categories = List.of(NotificationDataCategory.OBJECT_CONTENT);
        ValidationException ex = assertThrows(ValidationException.class, () -> gate.assertCanEnable(categories));
        assertTrue(ex.getMessage().contains("RA_PROFILE"), ex.getMessage());
        assertTrue(ex.getMessage().contains("MEMBERS"), ex.getMessage());
    }

    @Test
    void ungatedCategoriesNeverConsultPermissions() {
        assertDoesNotThrow(() -> gate()
                .assertCanEnable(List.of(NotificationDataCategory.METADATA, NotificationDataCategory.ASSOCIATIONS)));
        verify(authHelper, never()).loadObjectPermissions(any(), any());
    }

    @Test
    void gatedMarkerMatchesTheGateMap() {
        assertTrue(NotificationDataCategoryGate.isGated(NotificationDataCategory.CUSTOM_ATTRIBUTES));
        assertTrue(NotificationDataCategoryGate.isGated(NotificationDataCategory.OBJECT_CONTENT));
        assertFalse(NotificationDataCategoryGate.isGated(NotificationDataCategory.METADATA));
        assertFalse(NotificationDataCategoryGate.isGated(NotificationDataCategory.ASSOCIATIONS));
    }
}

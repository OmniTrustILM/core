# Design: OBJECT_CONTACT Recipient Type for Notification Profiles

## Overview

Allow a notification profile to resolve notification recipients from the triggering resource object itself, using the object's custom attributes and the existing mapping-attributes mechanism already used for USER and GROUP recipients. This enables sending notifications via whatever contact channel the connector supports (email, SMS, Slack, etc.) to an address stored on the object — e.g. a certificate's `contactEmail` custom attribute — without the sender needing to be a registered CZERTAINLY user.

The contact resolution is entirely connector-driven: which custom attribute to read, how to interpret it, and what channel to use are determined by the notification instance's mapping attributes configuration, not by any field on the notification profile.

## Scope

- One new `RecipientType`: `OBJECT_CONTACT`
- No new DB column — `NotificationProfileVersion` stores only `recipientType = OBJECT_CONTACT` and null `recipientUuids`
- `NotificationListener` resolves the recipient to the triggering object itself, then uses the existing `getMappedAttributes()` path for contact resolution
- Both repos affected: `CZERTAINLY-Interfaces` (enum, DTO validation) and `CZERTAINLY-Core` (listener, model)

## Data Model

### `RecipientType` enum (CZERTAINLY-Interfaces)

New value added:

```java
OBJECT_CONTACT("objectContact", "Object Contact",
    "Notification is sent to the contact of the triggering object, resolved via the notification instance's mapping attributes", null)
```

`recipientResource` is `null` — there is no User/Group/Role entity backing this type. The triggering object's resource and UUID are used at runtime.

### `NotificationProfileVersion` entity (CZERTAINLY-Core)

No new column. For `OBJECT_CONTACT` profiles, `recipientUuids` is null/empty and `recipientType = OBJECT_CONTACT`. No Flyway migration needed.

### DTOs (CZERTAINLY-Interfaces)

No new fields added to any DTO.

`NotificationProfileUpdateRequestDto` validation changes:

- `isRecipientValid()` (`@AssertTrue`): add `OBJECT_CONTACT` to both sides of the existing condition, alongside `OWNER`, `NONE`, and `DEFAULT` — types that require no `recipientUuids`. The USER/GROUP/ROLE branch (requires non-empty `recipientUuids`) also excludes `OBJECT_CONTACT` explicitly.
- A new `@AssertFalse isInternalNotificationInvalidForObjectContact()`: returns `true` (assertion fails) when `recipientType == OBJECT_CONTACT && internalNotification == true`. Internal notifications require a platform user UUID; `OBJECT_CONTACT` has none.
- The existing `isInternalNotificationPossible()` (`@AssertFalse`) is left unchanged — it covers `NONE` and `DEFAULT` only.

## Creation-Time Validation

No service-level validation required beyond the DTO `@AssertTrue`/`@AssertFalse` constraints. The notification profile stores `recipientType = OBJECT_CONTACT` with null `recipientUuids`, which is sufficient. Which custom attribute to read is determined at runtime by the notification instance's mapping attributes, not by anything stored on the profile.

## Runtime Behavior

### `NotificationListener.getRecipients()`

New `OBJECT_CONTACT` case:

1. Return `List.of(new NotificationRecipient(RecipientType.OBJECT_CONTACT, objectUuid))` — the triggering object's UUID becomes the recipient UUID.

No attribute reading happens at this stage. The actual contact resolution (which custom attribute, which channel) is deferred to `sendExternalNotifications()`.

### `sendExternalNotifications()`

At the point where recipient custom attributes are fetched for mapping (currently line 288 in `NotificationListener`):

```java
// Current code (for USER/GROUP — uses the recipient entity's custom attributes):
List<ResponseAttribute> recipientCustomAttributes =
    attributeEngine.getObjectCustomAttributesContent(
        recipient.getRecipientType().getRecipientResource(),
        recipient.getRecipientUuid());

// Updated code:
Resource customAttributeResource = recipient.getRecipientType() == RecipientType.OBJECT_CONTACT
    ? resource                                              // triggering object's resource type
    : recipient.getRecipientType().getRecipientResource(); // USER/GROUP entity resource
List<ResponseAttribute> recipientCustomAttributes =
    attributeEngine.getObjectCustomAttributesContent(customAttributeResource, recipient.getRecipientUuid());
```

For `OBJECT_CONTACT`: `resource` (the triggering object's resource, already a parameter of `sendExternalNotifications`) and `recipient.getRecipientUuid()` (= `objectUuid` set by `getRecipients()`) are used. The custom attributes of the triggering object are then passed to `getMappedAttributes()` exactly as USER/GROUP custom attributes are, and the connector receives the mapped values.

### `constructNotificationRecipientDto()`

New `OBJECT_CONTACT` case in the switch:

```java
case OBJECT_CONTACT -> {
    recipientDto = new NotificationRecipientDto();
    // No platform entity; name and contact details are resolved by the connector
    // via mapped attributes — not populated here
}
```

## Error Handling

If `getObjectCustomAttributesContent()` throws for an `OBJECT_CONTACT` recipient, the existing error handling in `sendExternalNotifications()` applies (same as for USER/GROUP failures). If the triggering object has no custom attributes matching what the connector's mapping attributes expect, `getMappedAttributes()` returns an empty list and the connector receives no mapped attributes for that recipient.

## Testing

### DTO validation (`NotificationProfileUpdateRequestDto`)

- `recipientType = OBJECT_CONTACT`, `recipientUuids = null`, `internalNotification = false` → valid
- `recipientType = OBJECT_CONTACT`, `recipientUuids` non-empty → invalid (caught by `isRecipientValid()` guard allowing only null/empty UUIDs for OBJECT_CONTACT)
- `recipientType = OBJECT_CONTACT`, `internalNotification = true` → invalid (caught by `isInternalNotificationInvalidForObjectContact()`)
- `recipientType = USER`, `recipientUuids` non-empty, `internalNotification = true` → still valid (existing behavior unchanged)
- `recipientType = NONE`, `internalNotification = true` → still invalid (existing `isInternalNotificationPossible()` unchanged)

### `NotificationListenerTest` (runtime behaviour)

- `OBJECT_CONTACT` profile → `getRecipients()` returns one recipient with `(OBJECT_CONTACT, objectUuid)`
- `sendExternalNotifications()` calls `getObjectCustomAttributesContent(resource, objectUuid)` — the triggering object's custom attributes
- Connector receives mapped attributes derived from the triggering object

## Files Affected

**CZERTAINLY-Interfaces:**
- `src/main/java/com/czertainly/api/model/core/notification/RecipientType.java`
- `src/main/java/com/czertainly/api/model/client/notification/NotificationProfileUpdateRequestDto.java`

**CZERTAINLY-Core:**
- `src/main/java/com/czertainly/core/messaging/jms/listeners/NotificationListener.java`

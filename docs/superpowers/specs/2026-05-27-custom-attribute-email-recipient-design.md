# Design: Custom Attribute Email Recipient for Notification Profiles

## Overview

Allow a notification profile to resolve its recipient email addresses from a STRING or TEXT custom attribute on the triggering resource object, rather than from a registered User, Group, or Role. This enables sending notifications to email addresses that are stored on the object itself — e.g. a certificate's `contactEmail` attribute — including addresses that do not belong to registered CZERTAINLY users.

## Scope

- One new `RecipientType`: `CUSTOM_ATTRIBUTE`
- `NotificationProfileVersion` stores the attribute name to read at runtime
- `NotificationListener` resolves the attribute, validates each value as an email address, and builds recipients
- Both repos affected: `CZERTAINLY-Interfaces` (enum, DTOs) and `CZERTAINLY-Core` (entity, service validation, listener, model)

## Data Model

### `RecipientType` enum (CZERTAINLY-Interfaces)

New value added:

```java
CUSTOM_ATTRIBUTE("customAttribute", "Custom Attribute",
    "Recipient email is read from a STRING or TEXT custom attribute on the triggering resource object", null)
```

`recipientResource` is `null` — there is no User/Group/Role entity backing this type.

### `NotificationProfileVersion` entity (CZERTAINLY-Core)

One new nullable column added via Flyway migration:

```java
@Column(name = "recipient_attribute_name")
private String recipientAttributeName;   // non-null only when recipientType = CUSTOM_ATTRIBUTE
```

### DTOs (CZERTAINLY-Interfaces)

`NotificationProfileUpdateRequestDto` gains `recipientAttributeName` (nullable String).
`NotificationProfileDetailDto` and `NotificationProfileResponseDto` gain the same field for read-back.

The existing `isRecipientValid()` `@AssertTrue` is updated to handle `CUSTOM_ATTRIBUTE`:
- `CUSTOM_ATTRIBUTE` requires `recipientAttributeName` non-blank and `recipientUuids` empty
- All other recipient types: `recipientAttributeName` is silently ignored even if set

The existing `isInternalNotificationPossible()` `@AssertFalse` is updated to also disallow `internalNotification=true` for `CUSTOM_ATTRIBUTE` — recipients are plain email addresses with no platform user UUIDs, so internal notifications cannot be created for them. `sendInternalNotifications` in `NotificationListener` already throws for unhandled recipient types, making this a required constraint.

## Creation-Time Validation

Performed in `NotificationProfileServiceImpl` when creating or updating a profile with `recipientType = CUSTOM_ATTRIBUTE`:

| # | Check | Error |
|---|-------|-------|
| 1 | `recipientAttributeName` is non-null and non-blank | Required when recipient type is CUSTOM_ATTRIBUTE |
| 2 | `recipientUuids` is empty | Recipient UUIDs must not be set for CUSTOM_ATTRIBUTE type |
| 3 | A custom attribute definition with that name exists and has `contentType = STRING` or `TEXT` | Attribute must exist and be of type STRING or TEXT |

Check 3 looks up the attribute definition by name. The profile does not know which resource type it will be used with, so resource-type association is not checked at creation time — handled gracefully at runtime.

For all other recipient types, `recipientAttributeName` is accepted silently without validation.

## Runtime Behavior

In `NotificationListener.getRecipients()`, new `CUSTOM_ATTRIBUTE` case:

1. Call `attributeEngine.getObjectCustomAttributesContent(resource, objectUuid)` — the same call already used in `sendExternalNotifications` for mapped attributes
2. Find the attribute matching `recipientAttributeName`
   - Not found or has no content values → write trigger history record (warning), return empty list
3. For each STRING/TEXT content value:
   - **Valid email** (contains `@`, valid domain part) → create `NotificationRecipient` with `recipientType = CUSTOM_ATTRIBUTE` and `email` field set (`recipientUuid` is null)
   - **Invalid email** → write trigger history record: `"Skipped invalid email address '<value>' from custom attribute '<name>'"`, skip this value, continue with remaining values
4. Return the list of valid recipients

### `NotificationRecipient` model change

`NotificationRecipient` gains an optional `email` field:

```java
private String email;   // non-null only for CUSTOM_ATTRIBUTE recipients
```

### `constructNotificationRecipientDto` change

New `CUSTOM_ATTRIBUTE` case in the switch:

```java
case CUSTOM_ATTRIBUTE -> {
    recipientDto = new NotificationRecipientDto();
    recipientDto.setEmail(recipient.getEmail());
    recipientDto.setName(recipient.getEmail());   // no entity name available
}
```

### Mapped attributes for CUSTOM_ATTRIBUTE recipients

`getMappedAttributes()` is called with the recipient's entity custom attributes. For `CUSTOM_ATTRIBUTE` recipients there is no backing entity, so an empty list is passed — no mapped attributes are sent to the connector for these recipients.

## Error Handling

All failures are non-fatal and per-value:

| Situation | Behaviour |
|-----------|-----------|
| Attribute not found on triggering object | Trigger history record written, nobody receives notification from this profile |
| Attribute found but has no values | Same as above |
| Attribute value is not a valid email | Trigger history record written, value skipped, remaining values still send |
| `attributeEngine` call throws | Caught, trigger history record written, nobody receives notification from this profile |

## Testing

### `NotificationProfileServiceTest` (creation-time validation)
- `recipientType = CUSTOM_ATTRIBUTE` with valid STRING attribute name → accepted
- `recipientType = CUSTOM_ATTRIBUTE` with valid TEXT attribute name → accepted
- `recipientType = CUSTOM_ATTRIBUTE` with `recipientAttributeName` null or blank → rejected
- `recipientType = CUSTOM_ATTRIBUTE` with non-empty `recipientUuids` → rejected
- `recipientType = CUSTOM_ATTRIBUTE` with attribute name pointing to a non-STRING/TEXT attribute → rejected
- `recipientType = CUSTOM_ATTRIBUTE` with attribute name not matching any definition → rejected
- `recipientType = USER` with `recipientAttributeName` set → accepted (silently ignored)
- `recipientType = CUSTOM_ATTRIBUTE` with `internalNotification = true` → rejected

### `NotificationListenerTest` (runtime behaviour)
- Attribute exists with one valid email → one notification sent
- Attribute exists with multiple valid emails → one notification per email
- Attribute exists with mix of valid and invalid emails → valid ones sent, invalid ones produce trigger history records
- Attribute not found on object → no notification sent, trigger history record written
- Attribute found but empty → no notification sent, trigger history record written

## Files Affected

**CZERTAINLY-Interfaces:**
- `src/main/java/com/czertainly/api/model/core/notification/RecipientType.java`
- `src/main/java/com/czertainly/api/model/client/notification/NotificationProfileUpdateRequestDto.java`
- `src/main/java/com/czertainly/api/model/client/notification/NotificationProfileDetailDto.java`
- `src/main/java/com/czertainly/api/model/client/notification/NotificationProfileResponseDto.java`

**CZERTAINLY-Core:**
- `src/main/resources/db/migration/V<next>__add_recipient_attribute_name_to_notification_profile_version.sql`
- `src/main/java/com/czertainly/core/dao/entity/notifications/NotificationProfileVersion.java`
- `src/main/java/com/czertainly/core/service/impl/NotificationProfileServiceImpl.java`
- `src/main/java/com/czertainly/core/messaging/model/NotificationRecipient.java`
- `src/main/java/com/czertainly/core/messaging/jms/listeners/NotificationListener.java`
- `src/test/java/com/czertainly/core/service/NotificationProfileServiceTest.java`
- `src/test/java/com/czertainly/core/messaging/jms/listeners/NotificationListenerTest.java` (create if not exists)

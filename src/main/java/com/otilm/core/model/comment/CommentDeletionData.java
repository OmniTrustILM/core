package com.otilm.core.model.comment;

import com.otilm.api.model.common.events.data.CommentEventData;
import java.util.List;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

/**
 * Audit data of a thread root's deletion, carrying the replies removed with it. Comments cannot be edited, so this
 * record is the only place their text survives; the event payload never carries them, which is why the field is not on
 * the event data itself.
 */
@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
public class CommentDeletionData extends CommentEventData {

    private List<CommentEventData> cascadedReplies;
}

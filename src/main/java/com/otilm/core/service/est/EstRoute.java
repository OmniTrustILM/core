package com.otilm.core.service.est;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.service.est.message.EstResponses;

/**
 * The profiles that serve one EST request, resolved once and passed down the call chain. The route is a read-only
 * snapshot: callers must not modify its entities. They are detached, as the EST endpoints are left out of open-in-view
 * and nothing around them keeps a persistence context open, so only what was loaded with them can be read: the columns
 * of the EST Profile, and the RA Profile with its authority and connector. Anything else is read by query.
 *
 * @param estProfile the EST Profile whose settings and authentication policy apply
 * @param raProfile the RA Profile that issues, with its authority and connector loaded
 * @param raProfileRoute whether the label named the RA Profile, so the issue attributes are those of its EST
 * activation, rather than the EST Profile, which issues through its default RA Profile
 * @param label the label of the request path, which the resolver found usable, {@code null} for a request without one
 */
public record EstRoute(EstProfile estProfile, RaProfile raProfile, boolean raProfileRoute, String label) {

    /**
     * @return the realm that a refusal of a request on this route names, which is the label, or
     * {@link EstResponses#DEFAULT_REALM} for a request without one
     */
    public String realm() {
        return label != null ? label : EstResponses.DEFAULT_REALM;
    }
}

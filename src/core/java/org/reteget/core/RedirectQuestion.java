package org.reteget.core;

import java.io.IOException;
import java.net.URL;

/**
 * An https download that the server redirects to plain http. The redirect is followed only after
 * the user agreed for the target's origin (scheme, host and port) on this queue entry; until then
 * the download stops with this question.
 */
public final class RedirectQuestion extends IOException implements UserQuestion {

    public static final String KIND = "downgrade";

    /** Host of the https address that redirected. */
    public final String fromHost;
    /** The http address the redirect leads to, without user info. */
    public final String target;

    RedirectQuestion(String fromHost, String target) {
        super("The server at " + fromHost + " redirects this https download to unencrypted http (" + target
                + "); confirm to continue without encryption");
        this.fromHost = fromHost;
        this.target = target;
    }

    /** http://host[:port] of the target: what the user's answer allows. */
    public String origin() {
        try {
            return HttpAuth.origin(new URL(target));
        } catch (IOException e) {
            return target;
        }
    }

    public String token() {
        return KIND + "\t" + fromHost + "\t" + target;
    }

    /** The question a token stands for, or null when it is not one. */
    public static RedirectQuestion fromToken(String token) {
        if (token == null) return null;
        String[] f = token.split("\t", -1);
        if (f.length != 3 || !KIND.equals(f[0]) || f[1].length() == 0) return null;
        if (!f[2].toLowerCase(java.util.Locale.US).startsWith("http://")) return null;
        return new RedirectQuestion(f[1], f[2]);
    }
}

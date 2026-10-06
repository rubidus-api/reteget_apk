package org.reteget.core;

/**
 * A download failure that is really a question for the user (confirm a server's key or
 * certificate, give a passphrase). The token travels in the queue record so that the question
 * can be put later, also after the app was closed.
 */
public interface UserQuestion {
    String token();
}

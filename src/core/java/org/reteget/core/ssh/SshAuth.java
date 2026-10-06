package org.reteget.core.ssh;

import java.io.IOException;

/**
 * User authentication (RFC 4252, RFC 4256): asks the server what it accepts, then tries the
 * chosen key, then the password, then keyboard-interactive with the same password. Runs only
 * after the transport has checked the host key.
 */
final class SshAuth {

    private SshAuth() {}

    static final int MSG_REQUEST = 50;
    static final int MSG_FAILURE = 51;
    static final int MSG_SUCCESS = 52;
    static final int MSG_BANNER = 53;
    static final int MSG_60 = 60; // PK_OK, PASSWD_CHANGEREQ or INFO_REQUEST, by method
    static final int MSG_INFO_RESPONSE = 61;

    private static final String SERVICE = "ssh-connection";

    /** What the server answered: success, or the methods that can continue. */
    private static final class Result {
        boolean success;
        boolean partial;
        String[] methods = new String[0];
        byte[] other; // a method-specific message (60)
    }

    /**
     * @param password null when the URL carried none
     * @param identity null when no key was chosen
     */
    static void authenticate(SshTransport t, String user, String password, SshIdentity identity) throws IOException {
        t.requestService("ssh-userauth");

        t.send(request(user, "none").bytes());
        Result r = read(t);
        if (r.success) return;
        String[] methods = r.methods;
        boolean triedSomething = false;

        if (identity != null && has(methods, "publickey")) {
            triedSomething = true;
            byte[] blob = identity.publicBlob();
            for (String alg : identity.algorithms(t.serverSigAlgs())) {
                t.send(request(user, "publickey").bool(false).string(alg).string(blob).bytes());
                r = read(t);
                if (r.success) return;
                if (r.other == null) { // refused for this algorithm
                    methods = r.methods;
                    continue;
                }
                byte[] signed = new SshBuf.Writer().string(t.sessionId()).raw(
                        request(user, "publickey").bool(true).string(alg).string(blob).bytes()).bytes();
                byte[] sig = new SshBuf.Writer().string(alg).string(identity.sign(alg, signed)).bytes();
                t.send(request(user, "publickey").bool(true).string(alg).string(blob).string(sig).bytes());
                r = read(t);
                if (r.success) return;
                methods = r.methods;
                break; // the server took the key but not the signature, or wants a second step
            }
        }

        if (password != null && has(methods, "password")) {
            triedSomething = true;
            t.send(request(user, "password").bool(false).string(password).bytes());
            r = read(t);
            if (r.success) return;
            if (r.other != null) {
                throw new SshException("the server wants the password changed first; do that with another SSH client");
            }
            methods = r.methods;
        }

        if (password != null && has(methods, "keyboard-interactive")) {
            triedSomething = true;
            t.send(request(user, "keyboard-interactive").string("").string("").bytes());
            while (true) {
                r = read(t);
                if (r.success) return;
                if (r.other == null) {
                    methods = r.methods;
                    break;
                }
                SshBuf.Reader in = new SshBuf.Reader(r.other, 1, r.other.length - 1);
                in.string(); // name
                in.string(); // instruction
                in.string(); // language
                long prompts = in.u32();
                SshBuf.Writer out = new SshBuf.Writer().u8(MSG_INFO_RESPONSE).u32(prompts);
                if (prompts > 1) {
                    throw new SshException("the server asks more than a password: " + SshHostKey.printable(in.text()));
                }
                if (prompts == 1) {
                    String prompt = in.text();
                    if (in.bool()) { // an echoed prompt is not a password prompt
                        throw new SshException("the server asks for something other than a password: "
                                + SshHostKey.printable(prompt));
                    }
                    out.string(password);
                }
                t.send(out.bytes());
            }
        }

        throw new SshException(failureText(methods, password != null, identity != null, triedSomething));
    }

    private static String failureText(String[] methods, boolean hadPassword, boolean hadKey, boolean tried) {
        StringBuilder list = new StringBuilder();
        for (String m : methods) {
            if (list.length() > 0) list.append(", ");
            list.append(SshHostKey.printable(m));
        }
        String accepts = list.length() > 0 ? " (the server accepts: " + list + ")" : "";
        if (tried) return "Authentication failed: check the user name, password or key" + accepts;
        if (!hadPassword && !hadKey && (has(methods, "password") || has(methods, "keyboard-interactive"))) {
            return "The server needs a password; put it in the URL, as in sftp://user:password@host/path" + accepts;
        }
        if (!hadKey && has(methods, "publickey")) return "The server needs a key; choose one for this address" + accepts;
        return "Authentication is not possible with what was given" + accepts;
    }

    private static SshBuf.Writer request(String user, String method) {
        return new SshBuf.Writer().u8(MSG_REQUEST).string(user).string(SERVICE).string(method);
    }

    private static boolean has(String[] list, String name) {
        for (String s : list) {
            if (s.equals(name)) return true;
        }
        return false;
    }

    private static Result read(SshTransport t) throws IOException {
        while (true) {
            byte[] p = t.receive();
            int type = p[0] & 0xff;
            Result r = new Result();
            if (type == MSG_BANNER) continue;
            if (type == MSG_SUCCESS) {
                r.success = true;
                return r;
            }
            if (type == MSG_FAILURE) {
                SshBuf.Reader in = new SshBuf.Reader(p, 1, p.length - 1);
                r.methods = in.nameList();
                r.partial = in.bool();
                return r;
            }
            if (type == MSG_60) {
                r.other = p;
                return r;
            }
            throw new SshException("unexpected SSH message " + type + " during authentication");
        }
    }
}

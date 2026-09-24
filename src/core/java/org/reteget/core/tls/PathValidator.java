package org.reteget.core.tls;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Certificate path validation from a server leaf to a trust anchor (RFC 5280 section 6,
 * reduced profile), using this package's own signature verifiers.
 *
 * Needed because Android 2.3 cannot verify ECDSA certificate signatures, and GitHub's
 * chain is ECDSA from leaf to root. The profile is deliberately fail-closed:
 *  - names chain by exact DER equality of issuer and subject;
 *  - every certificate is checked for validity at {@code now};
 *  - issuing certificates must be CA with keyCertSign (when keyUsage is present) and
 *    respect pathLenConstraint;
 *  - the leaf must allow serverAuth when it carries extendedKeyUsage;
 *  - unknown critical extensions, and name/policy constraints (not implemented here),
 *    reject the path;
 *  - SHA-1, MD5 and RSASSA-PSS certificate signatures are not accepted.
 * Revocation is not checked (neither does the platform trust manager on these releases).
 */
public final class PathValidator {

    public static final int MAX_DEPTH = 8;

    private PathValidator() {}

    /**
     * @param presented the chain the server sent, leaf first (order of the rest not trusted)
     * @param anchors   trusted root certificates
     * @return null when a valid path exists, otherwise the reason for the last failure
     */
    public static String validate(X509Cert[] presented, List<X509Cert> anchors, long now) {
        if (presented.length == 0) return "empty chain";
        X509Cert leaf = presented[0];
        String leafProblem = checkLeaf(leaf);
        if (leafProblem != null) return leafProblem;
        List<X509Cert> path = new ArrayList<X509Cert>();
        path.add(leaf);
        String[] reason = { "no path to a trusted root" };
        return extend(path, presented, anchors, now, reason) ? null : reason[0];
    }

    private static String checkLeaf(X509Cert leaf) {
        if (leaf.extKeyUsage != null && !leaf.extKeyUsage.contains(X509Cert.OID_EKU_SERVER_AUTH)
                && !leaf.extKeyUsage.contains(X509Cert.OID_EKU_ANY)) {
            return "leaf certificate is not for TLS servers";
        }
        if (leaf.keyUsage != -1 && (leaf.keyUsage & X509Cert.KU_DIGITAL_SIGNATURE) == 0) {
            return "leaf key usage does not allow signatures";
        }
        return null;
    }

    private static String checkCommon(X509Cert c, long now) {
        if (now < c.notBefore) return "certificate not yet valid (check the device clock)";
        if (now > c.notAfter) return "certificate expired";
        if (c.unknownCriticalExtension != null) return "unknown critical extension " + c.unknownCriticalExtension;
        if (c.hasUnsupportedConstraint) return "name or policy constraints are not supported";
        return null;
    }

    /** Depth-first search; path.get(path.size()-1) is the certificate whose issuer we look for. */
    private static boolean extend(List<X509Cert> path, X509Cert[] presented, List<X509Cert> anchors,
                                  long now, String[] reason) {
        X509Cert current = path.get(path.size() - 1);
        String problem = checkCommon(current, now);
        if (problem != null) {
            reason[0] = problem;
            return false;
        }
        // Issuing certificates below this one must allow this depth.
        int below = path.size() - 1; // non-leaf certificates already in the path under `current`'s issuer
        // Is `current` itself a trust anchor? Then the path is complete.
        for (X509Cert a : anchors) {
            if (a.sameCertificate(current)) return true;
        }
        // Anchors first: finishing at a root is preferred over a longer presented chain.
        for (X509Cert a : anchors) {
            if (Arrays.equals(a.subject, current.issuer) && current.isSignedBy(a.publicKey)) {
                if (!mayIssue(a, below, reason)) continue;
                if (now < a.notBefore || now > a.notAfter) {
                    reason[0] = "trusted root expired";
                    continue;
                }
                return true;
            }
        }
        if (path.size() >= MAX_DEPTH) {
            reason[0] = "certificate chain too long";
            return false;
        }
        for (int i = 1; i < presented.length; i++) {
            X509Cert cand = presented[i];
            if (path.contains(cand) || !Arrays.equals(cand.subject, current.issuer)) continue;
            if (!current.isSignedBy(cand.publicKey)) {
                reason[0] = "certificate signature does not verify";
                continue;
            }
            if (!mayIssue(cand, below, reason)) continue;
            path.add(cand);
            if (extend(path, presented, anchors, now, reason)) return true;
            path.remove(path.size() - 1);
        }
        return false;
    }

    /** @param intermediatesBelow number of CA certificates between this issuer and the leaf */
    private static boolean mayIssue(X509Cert issuer, int intermediatesBelow, String[] reason) {
        if (!issuer.isCa) {
            reason[0] = "issuer is not a CA";
            return false;
        }
        if (issuer.keyUsage != -1 && (issuer.keyUsage & X509Cert.KU_KEY_CERT_SIGN) == 0) {
            reason[0] = "issuer key usage does not allow certificate signing";
            return false;
        }
        if (issuer.pathLen >= 0 && intermediatesBelow > issuer.pathLen) {
            reason[0] = "path length constraint exceeded";
            return false;
        }
        return true;
    }
}

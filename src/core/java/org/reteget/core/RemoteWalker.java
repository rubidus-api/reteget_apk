package org.reteget.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Collects the files under the folders a user checked in a listing, with their place relative to
 * the folder, so that each can be queued into Download/&lt;folder&gt;/&lt;subpath&gt;. Bounded in
 * depth, number of files and number of listings, and never walks a folder twice (link loops).
 */
public final class RemoteWalker {

    public static final int MAX_DEPTH = 8;
    public static final int MAX_FILES = 1000;
    public static final int MAX_LISTINGS = 300;

    /** Reads one folder; the engine in the app, a fake in tests. */
    public interface Lister {
        List<RemoteEntry> list(String folderUrl) throws IOException;
    }

    /** A file to queue: its address, the folder path to save it in (relative, '/'-separated, "" = here) and its size. */
    public static final class Planned {
        public final String url;
        public final String subdir;
        public final String name;
        public final long size;

        Planned(String url, String subdir, String name, long size) {
            this.url = url;
            this.subdir = subdir;
            this.name = name;
            this.size = size;
        }
    }

    /** More than the limits allow; nothing is queued then. */
    public static final class TooManyException extends IOException {
        public final int limit;

        TooManyException(String what, int limit) {
            super("More than " + limit + " " + what);
            this.limit = limit;
        }
    }

    public interface Progress {
        /** Called before each listing; return false to stop (cancel). */
        boolean listing(String folderUrl, int filesSoFar);
    }

    /**
     * Files of the checked entries: a checked file as itself, a checked folder with everything
     * under it, saved under a folder of its own name.
     */
    public static List<Planned> plan(List<RemoteEntry> checked, Lister lister, Progress progress) throws IOException {
        List<Planned> out = new ArrayList<Planned>();
        Set<String> walked = new HashSet<String>();
        int[] listings = { 0 };
        for (RemoteEntry e : checked) {
            if (e.directory) {
                walk(e.url, e.name, 1, lister, progress, out, walked, listings);
            } else {
                add(out, new Planned(e.url, "", e.name, e.size));
            }
        }
        return out;
    }

    private static void walk(String folderUrl, String subdir, int depth, Lister lister, Progress progress,
                             List<Planned> out, Set<String> walked, int[] listings) throws IOException {
        if (!walked.add(Listings.stripUserInfo(folderUrl))) return;
        if (depth > MAX_DEPTH) throw new TooManyException("folder levels", MAX_DEPTH);
        if (++listings[0] > MAX_LISTINGS) throw new TooManyException("folders", MAX_LISTINGS);
        if (progress != null && !progress.listing(folderUrl, out.size())) throw new IOException("Cancelled");
        List<RemoteEntry> entries = lister.list(folderUrl);
        for (RemoteEntry e : entries) {
            if (!e.directory) add(out, new Planned(e.url, subdir, e.name, e.size));
        }
        for (RemoteEntry e : entries) {
            if (e.directory) walk(e.url, subdir + "/" + e.name, depth + 1, lister, progress, out, walked, listings);
        }
    }

    private static void add(List<Planned> out, Planned p) throws TooManyException {
        if (out.size() >= MAX_FILES) throw new TooManyException("files", MAX_FILES);
        out.add(p);
    }

    /** Sum of the known sizes. */
    public static long knownBytes(List<Planned> files) {
        long sum = 0;
        for (Planned p : files) if (p.size > 0) sum += p.size;
        return sum;
    }

    public static int unknownSizes(List<Planned> files) {
        int n = 0;
        for (Planned p : files) if (p.size < 0) n++;
        return n;
    }
}

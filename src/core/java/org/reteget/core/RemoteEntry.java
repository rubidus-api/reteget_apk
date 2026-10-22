package org.reteget.core;

/** One entry of a server folder listing: a file or a folder. */
public final class RemoteEntry {

    public final String name;
    public final boolean directory;
    /** Bytes, or -1 when the listing did not say. */
    public final long size;
    /** Milliseconds since 1970 (UTC), or 0 when the listing did not say. */
    public final long modified;
    /** The full address of the entry, with the folder address's user info kept (a download needs it); folders end in '/'. */
    public final String url;

    public RemoteEntry(String name, boolean directory, long size, long modified, String url) {
        this.name = name;
        this.directory = directory;
        this.size = size;
        this.modified = modified;
        this.url = url;
    }

    @Override
    public String toString() {
        return (directory ? "d " : "- ") + name + " " + size + " " + modified;
    }
}

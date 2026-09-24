package org.reteget.core;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * The download queue: runs downloads one at a time (gentle on old phones and slow links)
 * and keeps a persistent record of every entry until the user removes it.
 *
 * States: QUEUED -> RUNNING -> DONE | FAILED | CANCELLED. FAILED and CANCELLED entries can
 * be retried; any entry can be removed (a running one is cancelled first). Removing a DONE
 * entry forgets the record and keeps the file. Entries that were QUEUED or RUNNING when the
 * app process died come back as FAILED ("interrupted") so they can be retried.
 *
 * All methods are thread-safe. Listener callbacks run on the download thread or the caller's
 * thread; the UI must hop to its own thread.
 */
public final class DownloadQueue {

    public interface Listener {
        /** Any change: new entry, progress, state, removal. {@code task} is a snapshot, or null for "reload all". */
        void onTaskChanged(DownloadTask task);

        /** A download finished successfully. */
        void onTaskCompleted(DownloadTask task);
    }

    /** Persistence for the queue records (one string). */
    public interface Store {
        String load();

        void save(String data);
    }

    /** Runs one download; a new instance is created per attempt. */
    public interface Engine {
        void start(DownloadTask task, DownloadEngine.Listener listener);

        void cancel();

        String tlsSummary();
    }

    public interface EngineFactory {
        Engine create();
    }

    public static final String INTERRUPTED = "Interrupted: the app was closed during the download";

    private final List<DownloadTask> tasks = new ArrayList<DownloadTask>();
    private final Store store;
    private final EngineFactory engines;
    private volatile Listener listener;
    private DownloadTask running;
    private Engine runningEngine;
    private boolean removeRunningWhenStopped;
    private long nextId = 1;

    public DownloadQueue(Store store, EngineFactory engines) {
        this.store = store;
        this.engines = engines;
        String raw = store.load();
        if (raw != null) {
            for (String line : raw.split("\n")) {
                DownloadTask t = DownloadTask.fromJson(line);
                if (t == null) continue;
                if (t.isActive()) {
                    t.state = DownloadTask.State.FAILED;
                    t.error = INTERRUPTED;
                }
                tasks.add(t);
                nextId = Math.max(nextId, t.id + 1);
            }
        }
    }

    /** The real engine: {@link DownloadEngine} with the task's TLS settings. */
    public static EngineFactory defaultEngines() {
        return new EngineFactory() {
            @Override
            public Engine create() {
                final DownloadEngine e = new DownloadEngine();
                return new Engine() {
                    @Override
                    public void start(DownloadTask t, DownloadEngine.Listener l) {
                        e.download(t.url, new File(t.destDir), t.insecure, t.forceBuiltInTls, l);
                    }

                    @Override
                    public void cancel() {
                        e.cancel();
                    }

                    @Override
                    public String tlsSummary() {
                        return e.getLastTlsSummary();
                    }
                };
            }
        };
    }

    public void setListener(Listener l) {
        listener = l;
    }

    /** Entries in queue order (oldest first), as copies. */
    public synchronized List<DownloadTask> snapshot() {
        List<DownloadTask> out = new ArrayList<DownloadTask>();
        for (DownloadTask t : tasks) out.add(t.copy());
        return out;
    }

    public synchronized DownloadTask enqueue(String url, File destDir, boolean insecure, boolean forceBuiltInTls,
                                             String expectedChecksum) {
        return enqueue(url, destDir, insecure, forceBuiltInTls, expectedChecksum, null, null);
    }

    public synchronized DownloadTask enqueue(String url, File destDir, boolean insecure, boolean forceBuiltInTls,
                                             String expectedChecksum, String template, String version) {
        DownloadTask t = new DownloadTask(nextId++, url, destDir.getAbsolutePath(), insecure, forceBuiltInTls,
                expectedChecksum, System.currentTimeMillis());
        t.template = template;
        t.version = version;
        tasks.add(t);
        persist();
        changed(t);
        startNext();
        return t.copy();
    }

    /** Stops a queued or running entry; it stays in the list as CANCELLED. */
    public synchronized void cancel(long id) {
        DownloadTask t = find(id);
        if (t == null) return;
        if (t == running) {
            runningEngine.cancel();
        } else if (t.state == DownloadTask.State.QUEUED) {
            t.state = DownloadTask.State.CANCELLED;
            t.finishedAt = System.currentTimeMillis();
            persist();
            changed(t);
        }
    }

    /** Queues a FAILED or CANCELLED entry again. */
    public synchronized void retry(long id) {
        DownloadTask t = find(id);
        if (t == null || (t.state != DownloadTask.State.FAILED && t.state != DownloadTask.State.CANCELLED)) return;
        t.state = DownloadTask.State.QUEUED;
        t.error = null;
        t.bytesDone = 0;
        t.bytesTotal = -1;
        t.bytesPerSec = 0;
        t.finishedAt = 0;
        t.verified = false;
        t.sha256 = null;
        t.warning = null;
        persist();
        changed(t);
        startNext();
    }

    /** Removes an entry (cancelling it first if it is running). A downloaded file is kept. */
    public synchronized void remove(long id) {
        DownloadTask t = find(id);
        if (t == null) return;
        if (t == running) {
            removeRunningWhenStopped = true;
            runningEngine.cancel();
            return;
        }
        tasks.remove(t);
        persist();
        changed(null);
    }

    /** Removes every finished entry (done, failed, cancelled); returns how many. */
    public synchronized int clearFinished() {
        int n = 0;
        for (Iterator<DownloadTask> it = tasks.iterator(); it.hasNext();) {
            if (!it.next().isActive()) {
                it.remove();
                n++;
            }
        }
        if (n > 0) {
            persist();
            changed(null);
        }
        return n;
    }

    /** Records the result of the post-download checks (checksum, APK signature) for a DONE entry. */
    public synchronized void markVerified(long id, String sha256, String warning) {
        DownloadTask t = find(id);
        if (t == null || t.state != DownloadTask.State.DONE) return;
        t.verified = true;
        t.sha256 = sha256;
        t.warning = warning;
        persist();
        changed(t);
    }

    public synchronized boolean isBusy() {
        return running != null;
    }

    // ------------------------------------------------------------------ internals

    private DownloadTask find(long id) {
        for (DownloadTask t : tasks) {
            if (t.id == id) return t;
        }
        return null;
    }

    private void startNext() {
        if (running != null) return;
        for (DownloadTask t : tasks) {
            if (t.state == DownloadTask.State.QUEUED) {
                run(t);
                return;
            }
        }
    }

    private void run(final DownloadTask t) {
        running = t;
        removeRunningWhenStopped = false;
        t.state = DownloadTask.State.RUNNING;
        persist();
        changed(t);
        final Engine engine = engines.create();
        runningEngine = engine;
        engine.start(t.copy(), new DownloadEngine.Listener() {
            @Override
            public void onStart(String filename, long totalBytes) {
                synchronized (DownloadQueue.this) {
                    if (running != t) return;
                    t.fileName = filename;
                    t.bytesTotal = totalBytes;
                    persist();
                    changed(t);
                }
            }

            @Override
            public void onProgress(long bytesRead, long totalBytes, int percent, long bytesPerSec) {
                synchronized (DownloadQueue.this) {
                    if (running != t) return;
                    t.bytesDone = bytesRead;
                    if (totalBytes > 0) t.bytesTotal = totalBytes;
                    t.bytesPerSec = bytesPerSec;
                    changed(t);
                }
            }

            @Override
            public void onComplete(File destinationFile) {
                DownloadTask done;
                synchronized (DownloadQueue.this) {
                    if (running != t) return;
                    t.state = DownloadTask.State.DONE;
                    t.filePath = destinationFile.getAbsolutePath();
                    t.fileName = destinationFile.getName();
                    t.bytesDone = destinationFile.length();
                    t.bytesTotal = t.bytesDone;
                    t.tlsSummary = engine.tlsSummary();
                    done = t.copy();
                    finish(t);
                }
                Listener l = listener;
                if (l != null) l.onTaskCompleted(done);
                kick();
            }

            @Override
            public void onError(Exception ex) {
                synchronized (DownloadQueue.this) {
                    if (running != t) return;
                    t.state = DownloadTask.State.FAILED;
                    String m = ex.getMessage();
                    t.error = m != null && !m.isEmpty() ? m : ex.getClass().getSimpleName();
                    t.tlsSummary = engine.tlsSummary();
                    finish(t);
                }
                kick();
            }

            @Override
            public void onCancel() {
                synchronized (DownloadQueue.this) {
                    if (running != t) return;
                    t.state = DownloadTask.State.CANCELLED;
                    finish(t);
                }
                kick();
            }
        });
    }

    /** Caller holds the lock. */
    private void finish(DownloadTask t) {
        t.finishedAt = System.currentTimeMillis();
        t.bytesPerSec = 0;
        running = null;
        runningEngine = null;
        if (removeRunningWhenStopped) {
            tasks.remove(t);
            removeRunningWhenStopped = false;
            persist();
            changed(null);
        } else {
            persist();
            changed(t);
        }
    }

    private synchronized void kick() {
        startNext();
    }

    private void persist() {
        StringBuilder sb = new StringBuilder();
        for (DownloadTask t : tasks) {
            sb.append(t.toJson()).append('\n');
        }
        store.save(sb.toString());
    }

    private void changed(DownloadTask t) {
        Listener l = listener;
        if (l != null) l.onTaskChanged(t == null ? null : t.copy());
    }
}

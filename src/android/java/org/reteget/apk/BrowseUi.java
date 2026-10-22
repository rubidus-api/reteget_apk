package org.reteget.apk;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.reteget.core.DownloadEngine;
import org.reteget.core.DownloadTask;
import org.reteget.core.HttpAuth;
import org.reteget.core.IndexMatcher;
import org.reteget.core.Listings;
import org.reteget.core.RedirectQuestion;
import org.reteget.core.RemoteEntry;
import org.reteget.core.RemoteWalker;
import org.reteget.core.UserQuestion;

/**
 * Browsing a server folder (RFC-0005): the list of a folder, moving between folders, checking
 * files and folders and queueing them, checked folders with everything under them. Plain
 * AlertDialogs and a ListView, so it works from Android 2.3 on.
 */
final class BrowseUi {

    /** What the activity does with the user's choice. */
    interface Host {
        boolean insecure();

        /** The key chosen for sftp:// addresses, or null. */
        String sshKey();

        /** Queues {@code files}; each goes into the Download folder plus its subfolder. */
        void queue(List<RemoteWalker.Planned> files);
    }

    /** Dialog text on Android 2.3 is light on a dark frame; later the dialog's own theme decides. */
    private static final int LABEL = 0xFFCCCCCC;

    private final MainActivity a;
    private final SshUi sshUi;
    private final Host host;
    /** http origins the user let a listing be redirected to, for this run of the app. */
    private String allowHttp;

    BrowseUi(MainActivity activity, SshUi sshUi, Host host) {
        this.a = activity;
        this.sshUi = sshUi;
        this.host = host;
    }

    /** Opens the folder of {@code url} (the folder itself when it ends in '/'). */
    void open(String url) {
        if (url == null || url.trim().length() == 0) {
            Toast.makeText(a, R.string.toast_url_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        load(Listings.folderOf(url.trim()));
    }

    private DownloadEngine engine() {
        DownloadEngine e = new DownloadEngine();
        e.allowHttpRedirects(allowHttp);
        return e;
    }

    // --- reading a folder ---

    private interface Loaded {
        void done(List<RemoteEntry> entries);
    }

    private void load(final String folder) {
        read(folder, new Loaded() {
            public void done(List<RemoteEntry> entries) {
                show(folder, entries);
            }
        });
    }

    /** Lists {@code folder} in the background; questions are put and the listing tried again. */
    private void read(final String folder, final Loaded then) {
        final DownloadEngine e = engine();
        final ProgressDialog pd = ProgressDialog.show(a, null, a.getString(R.string.browse_reading, HttpAuth.mask(folder)), true, true,
                new DialogInterface.OnCancelListener() {
                    public void onCancel(DialogInterface dialog) {
                        e.cancel();
                    }
                });
        new Thread(new Runnable() {
            public void run() {
                List<RemoteEntry> got = null;
                IOException error = null;
                try {
                    got = e.list(folder, host.insecure(), Listings.folderOf(folder).toLowerCase().startsWith("sftp://") ? host.sshKey() : null);
                } catch (IOException ex) {
                    error = ex;
                } catch (RuntimeException ex) {
                    error = new IOException(String.valueOf(ex.getMessage()), ex);
                }
                final List<RemoteEntry> entries = got;
                final IOException err = error;
                a.runOnUiThread(new Runnable() {
                    public void run() {
                        try {
                            pd.dismiss();
                        } catch (Exception ignored) {
                        }
                        if (a.isFinishing() || e.isCancelled()) return;
                        if (err == null) {
                            then.done(entries);
                        } else {
                            failed(err, new Runnable() {
                                public void run() {
                                    read(folder, then);
                                }
                            });
                        }
                    }
                });
            }
        }, "BrowseList").start();
    }

    /** An error, or a question whose answer lets {@code again} run. */
    private void failed(IOException err, final Runnable again) {
        if (err instanceof RedirectQuestion) {
            final RedirectQuestion r = (RedirectQuestion) err;
            new AlertDialog.Builder(a)
                    .setTitle(R.string.redirect_title)
                    .setMessage(a.getString(R.string.redirect_msg, r.fromHost, r.target))
                    .setPositiveButton(R.string.redirect_btn_continue, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            allowHttp = allowHttp == null ? r.origin() : allowHttp + " " + r.origin();
                            again.run();
                        }
                    })
                    .setNegativeButton(R.string.btn_cancel, null)
                    .show();
            return;
        }
        if (err instanceof UserQuestion) {
            DownloadTask question = new DownloadTask(-1, "", "", false, false, "", 0);
            question.state = DownloadTask.State.FAILED;
            question.ask = ((UserQuestion) err).token();
            sshUi.answer(question, again);
            return;
        }
        Toast.makeText(a, a.getString(R.string.browse_failed, HttpAuth.mask(String.valueOf(err.getMessage()))), Toast.LENGTH_LONG).show();
    }

    // --- the list ---

    private static void sort(List<RemoteEntry> entries) {
        Collections.sort(entries, new Comparator<RemoteEntry>() {
            public int compare(RemoteEntry x, RemoteEntry y) {
                if (x.directory != y.directory) return x.directory ? -1 : 1;
                return IndexMatcher.naturalCompare(x.name.toLowerCase(), y.name.toLowerCase());
            }
        });
    }

    private void show(final String folder, final List<RemoteEntry> entries) {
        sort(entries);
        final Set<RemoteEntry> checked = new HashSet<RemoteEntry>();
        AlertDialog.Builder b = new AlertDialog.Builder(a);
        final Context c = Build.VERSION.SDK_INT >= 11 ? b.getContext() : a;
        final boolean old = Build.VERSION.SDK_INT < 11;
        final String parent = Listings.parentOf(folder);
        final AlertDialog[] dialog = new AlertDialog[1];

        LinearLayout box = new LinearLayout(c);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (8 * a.getResources().getDisplayMetrics().density);
        TextView path = new TextView(c);
        path.setText(HttpAuth.mask(folder));
        path.setTextSize(12);
        path.setPadding(pad * 2, pad, pad * 2, pad);
        if (old) path.setTextColor(LABEL);
        box.addView(path);
        if (entries.isEmpty()) {
            TextView empty = new TextView(c);
            empty.setText(R.string.browse_empty);
            empty.setPadding(pad * 2, pad, pad * 2, pad * 2);
            if (old) empty.setTextColor(LABEL);
            box.addView(empty);
        }
        final ListView list = new ListView(c);
        final BaseAdapter adapter = new BaseAdapter() {
            public int getCount() {
                return entries.size();
            }

            public Object getItem(int i) {
                return entries.get(i);
            }

            public long getItemId(int i) {
                return i;
            }

            public View getView(int i, View reuse, ViewGroup parentView) {
                Row row = reuse instanceof Row ? (Row) reuse : new Row(c, old, pad);
                final RemoteEntry e = entries.get(i);
                row.bind(e, checked.contains(e), describe(e));
                row.check.setOnClickListener(new View.OnClickListener() {
                    public void onClick(View v) {
                        if (((CheckBox) v).isChecked()) checked.add(e); else checked.remove(e);
                        updateButton(dialog[0], checked.size());
                    }
                });
                return row;
            }
        };
        list.setAdapter(adapter);
        list.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            public void onItemClick(AdapterView<?> av, View v, int i, long id) {
                RemoteEntry e = entries.get(i);
                if (e.directory) {
                    dialog[0].dismiss();
                    load(e.url);
                } else {
                    if (!checked.add(e)) checked.remove(e);
                    adapter.notifyDataSetChanged();
                    updateButton(dialog[0], checked.size());
                }
            }
        });
        box.addView(list, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.FILL_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        b.setTitle(R.string.browse_title)
                .setView(box)
                .setPositiveButton(a.getString(R.string.browse_download, 0), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface d, int which) {
                        List<RemoteEntry> picked = new ArrayList<RemoteEntry>();
                        for (RemoteEntry e : entries) if (checked.contains(e)) picked.add(e);
                        collect(picked);
                    }
                })
                .setNegativeButton(R.string.browse_close, null);
        if (parent != null) {
            b.setNeutralButton(R.string.browse_up, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int which) {
                    load(parent);
                }
            });
        }
        dialog[0] = b.create();
        dialog[0].setOnShowListener(new DialogInterface.OnShowListener() {
            public void onShow(DialogInterface d) {
                updateButton(dialog[0], 0);
            }
        });
        dialog[0].show();
    }

    private void updateButton(AlertDialog d, int n) {
        if (d == null) return;
        View btn = d.getButton(DialogInterface.BUTTON_POSITIVE);
        if (btn instanceof TextView) {
            ((TextView) btn).setText(a.getString(R.string.browse_download, n));
            btn.setEnabled(n > 0);
        }
    }

    private String describe(RemoteEntry e) {
        StringBuilder sb = new StringBuilder();
        if (!e.directory && e.size >= 0) sb.append(size(e.size));
        if (e.modified > 0) {
            if (sb.length() > 0) sb.append("  ");
            sb.append(DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(e.modified)));
        }
        return sb.toString();
    }

    static String size(long b) {
        if (b < 1024) return b + " B";
        int exp = (int) (Math.log(b) / Math.log(1024));
        if (exp > 6) exp = 6;
        return String.format(java.util.Locale.US, "%.1f %sB", b / Math.pow(1024, exp), "KMGTPE".charAt(exp - 1));
    }

    /** One line of the list: a check box, the name (folders with '/') and size and date. */
    private static final class Row extends LinearLayout {
        final CheckBox check;
        final TextView name;
        final TextView info;

        Row(Context c, boolean old, int pad) {
            super(c);
            setOrientation(HORIZONTAL);
            setPadding(pad, pad / 2, pad, pad / 2);
            setDescendantFocusability(FOCUS_BLOCK_DESCENDANTS);
            check = new CheckBox(c);
            check.setFocusable(false);
            addView(check);
            LinearLayout text = new LinearLayout(c);
            text.setOrientation(VERTICAL);
            name = new TextView(c);
            name.setTextSize(15);
            info = new TextView(c);
            info.setTextSize(11);
            if (old) {
                name.setTextColor(LABEL);
                info.setTextColor(LABEL);
            }
            text.addView(name);
            text.addView(info);
            addView(text, new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
        }

        void bind(RemoteEntry e, boolean on, String details) {
            check.setChecked(on);
            name.setText(e.directory ? e.name + "/" : e.name);
            info.setText(details);
            info.setVisibility(details.length() > 0 ? VISIBLE : GONE);
        }
    }

    // --- queueing ---

    /** Checked files go as they are; checked folders are walked first, then confirmed. */
    private void collect(final List<RemoteEntry> picked) {
        if (picked.isEmpty()) return;
        boolean anyFolder = false;
        for (RemoteEntry e : picked) anyFolder |= e.directory;
        if (!anyFolder) {
            try {
                host.queue(RemoteWalker.plan(picked, null, null));
            } catch (IOException e) {
                Toast.makeText(a, String.valueOf(e.getMessage()), Toast.LENGTH_LONG).show();
            }
            return;
        }
        final boolean[] stop = { false };
        final DownloadEngine[] current = { null };
        final ProgressDialog pd = ProgressDialog.show(a, null, a.getString(R.string.browse_walking, 0), true, true,
                new DialogInterface.OnCancelListener() {
                    public void onCancel(DialogInterface dialog) {
                        stop[0] = true;
                        DownloadEngine e = current[0];
                        if (e != null) e.cancel();
                    }
                });
        new Thread(new Runnable() {
            public void run() {
                List<RemoteWalker.Planned> got = null;
                IOException error = null;
                try {
                    got = RemoteWalker.plan(picked, new RemoteWalker.Lister() {
                        public List<RemoteEntry> list(String folderUrl) throws IOException {
                            DownloadEngine e = engine();
                            current[0] = e;
                            return e.list(folderUrl, host.insecure(), folderUrl.toLowerCase().startsWith("sftp://") ? host.sshKey() : null);
                        }
                    }, new RemoteWalker.Progress() {
                        public boolean listing(String folderUrl, final int filesSoFar) {
                            a.runOnUiThread(new Runnable() {
                                public void run() {
                                    pd.setMessage(a.getString(R.string.browse_walking, filesSoFar));
                                }
                            });
                            return !stop[0];
                        }
                    });
                } catch (IOException ex) {
                    error = ex;
                }
                final List<RemoteWalker.Planned> files = got;
                final IOException err = error;
                a.runOnUiThread(new Runnable() {
                    public void run() {
                        try {
                            pd.dismiss();
                        } catch (Exception ignored) {
                        }
                        if (a.isFinishing() || stop[0]) return;
                        if (err instanceof RemoteWalker.TooManyException) {
                            Toast.makeText(a, a.getString(R.string.browse_too_many, err.getMessage()), Toast.LENGTH_LONG).show();
                        } else if (err != null) {
                            failed(err, new Runnable() {
                                public void run() {
                                    collect(picked);
                                }
                            });
                        } else {
                            confirm(files);
                        }
                    }
                });
            }
        }, "BrowseWalk").start();
    }

    private void confirm(final List<RemoteWalker.Planned> files) {
        if (files.isEmpty()) {
            Toast.makeText(a, R.string.browse_nothing, Toast.LENGTH_LONG).show();
            return;
        }
        int unknown = RemoteWalker.unknownSizes(files);
        String msg = a.getString(R.string.browse_confirm, files.size(), size(RemoteWalker.knownBytes(files)))
                + (unknown > 0 ? "\n" + a.getString(R.string.browse_confirm_unknown, unknown) : "");
        new AlertDialog.Builder(a)
                .setTitle(R.string.browse_title)
                .setMessage(msg)
                .setPositiveButton(R.string.btn_download, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface d, int which) {
                        host.queue(files);
                    }
                })
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    /** The folder a planned file is saved in: {@code base} plus its subfolders, each made safe as a file name. */
    static File target(File base, String subdir) {
        File d = base;
        if (subdir == null || subdir.length() == 0) return d;
        for (String part : subdir.split("/")) {
            String safe = DownloadEngine.safeFileName(part);
            if (safe.length() == 0 || safe.equals(".") || safe.equals("..")) continue;
            d = new File(d, safe);
        }
        return d;
    }
}

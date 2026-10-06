package org.reteget.apk;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.text.InputType;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;
import org.reteget.core.DownloadTask;
import org.reteget.core.ssh.KnownHosts;
import org.reteget.core.ssh.SshConfig;
import org.reteget.core.ssh.SshKeyFile;
import org.reteget.core.ssh.SshKeyStore;
import org.reteget.core.ssh.SshPromptException;

/**
 * The screens of sftp:// downloads: confirming a server's host key, the user's keys (generate,
 * import, passphrase, public key, delete), choosing the key for an address, and asking for a
 * key's passphrase. Everything is a plain AlertDialog, so it works from Android 2.3 on.
 */
final class SshUi {

    private static final String PREFS = "reteget_ssh";
    private static final String KEY_HOSTS = "known_hosts";
    private static final String KEY_KEYS = "keys";
    /** Dialog labels: the app theme's text is dark, but the (pre-Holo) dialog frame is dark. */
    private static final int LABEL = 0xFFCCCCCC;

    /** What the user picked; an empty string means "no key". */
    interface Picked {
        void onPicked(String fingerprint);
    }

    private final MainActivity a;

    SshUi(MainActivity activity) {
        this.a = activity;
    }

    /** Opens the host key record and the key store from the app's storage; once per process. */
    static synchronized void init(Context context) {
        if (sInitialised) return;
        final SharedPreferences sp = context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        KnownHosts hosts = new KnownHosts(new KnownHosts.Store() {
            public String load() {
                return sp.getString(KEY_HOSTS, null);
            }

            public void save(String data) {
                sp.edit().putString(KEY_HOSTS, data).commit();
            }
        });
        SshKeyStore keys = new SshKeyStore(new SshKeyStore.Store() {
            public String load() {
                return sp.getString(KEY_KEYS, null);
            }

            public void save(String data) {
                sp.edit().putString(KEY_KEYS, data).commit();
            }
        });
        SshConfig.set(hosts, keys);
        sInitialised = true;
    }

    private static boolean sInitialised;

    /** The name to show for a chosen key. */
    String keyLabel(String fingerprint) {
        if (fingerprint == null || fingerprint.length() == 0) return a.getString(R.string.ssh_key_none);
        SshKeyStore.Key k = SshConfig.keys().find(fingerprint);
        return k == null ? a.getString(R.string.ssh_key_missing) : k.name;
    }

    // --- choosing a key ---

    void pickKey(final Picked picked) {
        final List<SshKeyStore.Key> keys = SshConfig.keys().list();
        final String[] items = new String[keys.size() + 2];
        items[0] = a.getString(R.string.ssh_key_none);
        for (int i = 0; i < keys.size(); i++) items[i + 1] = describe(keys.get(i));
        items[items.length - 1] = a.getString(R.string.ssh_keys_manage);
        new AlertDialog.Builder(a)
                .setTitle(R.string.ssh_key_pick_title)
                .setItems(items, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        if (which == 0) {
                            picked.onPicked("");
                        } else if (which == items.length - 1) {
                            manageKeys(new Runnable() {
                                public void run() {
                                    pickKey(picked);
                                }
                            });
                        } else {
                            picked.onPicked(keys.get(which - 1).fingerprint);
                        }
                    }
                })
                .show();
    }

    private String describe(SshKeyStore.Key k) {
        return k.name + " (" + (k.type.startsWith("ssh-") ? k.type.substring(4) : k.type)
                + (k.isProtected ? ", " + a.getString(R.string.ssh_key_protected) : "") + ")";
    }

    // --- the user's keys ---

    /** The list of keys with its actions; {@code onClose} runs when the list is left. */
    void manageKeys(final Runnable onClose) {
        final List<SshKeyStore.Key> keys = SshConfig.keys().list();
        final String[] items = new String[keys.size()];
        for (int i = 0; i < items.length; i++) items[i] = describe(keys.get(i)) + "\n" + keys.get(i).fingerprint;
        AlertDialog.Builder b = new AlertDialog.Builder(a).setTitle(R.string.ssh_keys_title);
        if (items.length == 0) {
            b.setMessage(R.string.ssh_keys_empty);
        } else {
            b.setItems(items, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    keyActions(keys.get(which), onClose);
                }
            });
        }
        b.setPositiveButton(R.string.ssh_key_generate, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                generate(onClose);
            }
        });
        b.setNeutralButton(R.string.ssh_key_import, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                importKey(onClose);
            }
        });
        b.setNegativeButton(R.string.ssh_close, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                if (onClose != null) onClose.run();
            }
        });
        b.show();
    }

    private void keyActions(final SshKeyStore.Key k, final Runnable onClose) {
        String[] actions = { a.getString(R.string.ssh_key_show_public),
                a.getString(k.isProtected ? R.string.ssh_key_change_passphrase : R.string.ssh_key_set_passphrase),
                a.getString(R.string.ssh_key_delete) };
        new AlertDialog.Builder(a)
                .setTitle(k.name)
                .setItems(actions, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        if (which == 0) {
                            showPublicKey(k, onClose);
                        } else if (which == 1) {
                            changePassphrase(k, onClose);
                        } else {
                            new AlertDialog.Builder(a)
                                    .setMessage(a.getString(R.string.ssh_key_delete_confirm, k.name))
                                    .setPositiveButton(R.string.ssh_key_delete, new DialogInterface.OnClickListener() {
                                        public void onClick(DialogInterface d, int w) {
                                            SshConfig.keys().remove(k.fingerprint);
                                            manageKeys(onClose);
                                        }
                                    })
                                    .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        public void onClick(DialogInterface d, int w) {
                                            manageKeys(onClose);
                                        }
                                    })
                                    .show();
                        }
                    }
                })
                .setNegativeButton(R.string.ssh_close, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        manageKeys(onClose);
                    }
                })
                .show();
    }

    private void showPublicKey(final SshKeyStore.Key k, final Runnable onClose) {
        final String line = k.publicKeyLine();
        new AlertDialog.Builder(a)
                .setTitle(R.string.ssh_key_public_title)
                .setMessage(a.getString(R.string.ssh_key_public_msg, line, k.fingerprint))
                .setPositiveButton(R.string.ssh_copy, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        a.copyToClipboard(line);
                        Toast.makeText(a, R.string.ssh_key_public_copied, Toast.LENGTH_SHORT).show();
                        manageKeys(onClose);
                    }
                })
                .setNegativeButton(R.string.ssh_close, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        manageKeys(onClose);
                    }
                })
                .show();
    }

    private LinearLayout form() {
        LinearLayout l = new LinearLayout(a);
        l.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * a.getResources().getDisplayMetrics().density);
        l.setPadding(pad, pad / 2, pad, pad / 2);
        return l;
    }

    private EditText field(LinearLayout form, int label, boolean password) {
        TextView t = new TextView(a);
        t.setText(label);
        t.setTextColor(LABEL);
        form.addView(t);
        EditText e = new EditText(a);
        e.setSingleLine(true);
        if (password) e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        form.addView(e);
        return e;
    }

    /** Runs {@code work} off the UI thread behind a "please wait" (key derivation takes seconds on old phones). */
    private void busy(final Work work) {
        final ProgressDialog pd = ProgressDialog.show(a, null, a.getString(R.string.ssh_working), true, false);
        new Thread(new Runnable() {
            public void run() {
                String error = null;
                try {
                    work.run();
                } catch (Exception e) {
                    error = e.getMessage() != null ? e.getMessage() : e.toString();
                }
                final String err = error;
                a.runOnUiThread(new Runnable() {
                    public void run() {
                        try {
                            pd.dismiss();
                        } catch (Exception ignored) {
                        }
                        if (a.isFinishing()) return;
                        work.done(err);
                    }
                });
            }
        }, "SshKeyWork").start();
    }

    private abstract static class Work {
        abstract void run() throws Exception;

        /** On the UI thread; {@code error} is null when run() succeeded. */
        abstract void done(String error);
    }

    private void generate(final Runnable onClose) {
        LinearLayout f = form();
        final EditText name = field(f, R.string.ssh_key_name, false);
        final EditText p1 = field(f, R.string.ssh_key_passphrase_new, true);
        final EditText p2 = field(f, R.string.ssh_key_passphrase_again, true);
        new AlertDialog.Builder(a)
                .setTitle(R.string.ssh_key_generate_title)
                .setView(f)
                .setPositiveButton(R.string.ssh_key_generate, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        final String n = name.getText().toString().trim();
                        final String pass = p1.getText().toString();
                        if (!pass.equals(p2.getText().toString())) {
                            Toast.makeText(a, R.string.ssh_key_passphrase_mismatch, Toast.LENGTH_LONG).show();
                            generate(onClose);
                            return;
                        }
                        final SshKeyStore.Key[] made = new SshKeyStore.Key[1];
                        busy(new Work() {
                            void run() throws Exception {
                                made[0] = SshConfig.keys().generate(n, pass.length() > 0 ? pass : null);
                                if (pass.length() > 0) SshConfig.keys().unlock(made[0].fingerprint, pass);
                            }

                            void done(String error) {
                                if (error != null) {
                                    Toast.makeText(a, error, Toast.LENGTH_LONG).show();
                                    manageKeys(onClose);
                                } else {
                                    showPublicKey(made[0], onClose);
                                }
                            }
                        });
                    }
                })
                .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        manageKeys(onClose);
                    }
                })
                .show();
    }

    private static String readFile(String path) throws Exception {
        File f = new File(path);
        if (!f.isFile() || f.length() > 64 * 1024) throw new java.io.IOException("Cannot read a key file at " + path);
        InputStream in = new FileInputStream(f);
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            return out.toString("UTF-8");
        } finally {
            in.close();
        }
    }

    private void importKey(final Runnable onClose) {
        LinearLayout f = form();
        final EditText name = field(f, R.string.ssh_key_name, false);
        TextView t = new TextView(a);
        t.setText(R.string.ssh_key_import_hint);
        t.setTextColor(LABEL);
        f.addView(t);
        final EditText text = new EditText(a);
        text.setSingleLine(false);
        text.setMinLines(3);
        text.setMaxLines(6);
        text.setTextSize(11);
        f.addView(text);
        final EditText pass = field(f, R.string.ssh_key_passphrase_import, true);
        new AlertDialog.Builder(a)
                .setTitle(R.string.ssh_key_import_title)
                .setView(f)
                .setPositiveButton(R.string.ssh_key_import, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        final String n = name.getText().toString().trim();
                        final String src = text.getText().toString().trim();
                        final String pw = pass.getText().toString();
                        final SshKeyStore.Key[] made = new SshKeyStore.Key[1];
                        busy(new Work() {
                            void run() throws Exception {
                                String keyText = src.startsWith("/") && src.indexOf('\n') < 0 ? readFile(src) : src;
                                SshKeyFile file = SshKeyFile.parse(keyText);
                                if (file.isProtected()) {
                                    file.unlock(pw); // the passphrase must fit before the key is stored
                                } else if (pw.length() > 0) {
                                    file = file.withPassphrase(null, pw);
                                }
                                made[0] = SshConfig.keys().add(n, file);
                                if (pw.length() > 0) SshConfig.keys().unlock(made[0].fingerprint, pw);
                            }

                            void done(String error) {
                                if (error != null) {
                                    Toast.makeText(a, error, Toast.LENGTH_LONG).show();
                                } else {
                                    Toast.makeText(a, a.getString(made[0].isProtected ? R.string.ssh_key_imported
                                            : R.string.ssh_key_imported_unprotected, made[0].name), Toast.LENGTH_LONG).show();
                                }
                                manageKeys(onClose);
                            }
                        });
                    }
                })
                .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        manageKeys(onClose);
                    }
                })
                .show();
    }

    private void changePassphrase(final SshKeyStore.Key k, final Runnable onClose) {
        LinearLayout f = form();
        final EditText old = k.isProtected ? field(f, R.string.ssh_key_passphrase_current, true) : null;
        final EditText p1 = field(f, R.string.ssh_key_passphrase_new, true);
        final EditText p2 = field(f, R.string.ssh_key_passphrase_again, true);
        new AlertDialog.Builder(a)
                .setTitle(k.name)
                .setView(f)
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        final String o = old == null ? null : old.getText().toString();
                        final String n = p1.getText().toString();
                        if (!n.equals(p2.getText().toString())) {
                            Toast.makeText(a, R.string.ssh_key_passphrase_mismatch, Toast.LENGTH_LONG).show();
                            changePassphrase(k, onClose);
                            return;
                        }
                        busy(new Work() {
                            void run() throws Exception {
                                SshConfig.keys().setPassphrase(k.fingerprint, o, n.length() > 0 ? n : null);
                                if (n.length() > 0) SshConfig.keys().unlock(k.fingerprint, n);
                            }

                            void done(String error) {
                                Toast.makeText(a, error != null ? error : a.getString(n.length() > 0
                                        ? R.string.ssh_key_passphrase_set : R.string.ssh_key_passphrase_removed),
                                        Toast.LENGTH_LONG).show();
                                manageKeys(onClose);
                            }
                        });
                    }
                })
                .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        manageKeys(onClose);
                    }
                })
                .show();
    }

    // --- questions of a waiting download ---

    /** The short status text for a queue entry that waits for an answer, or null when it does not. */
    String waitingText(DownloadTask t) {
        SshPromptException q = SshPromptException.fromToken(t.ask);
        if (q == null) return null;
        if (SshPromptException.PASSPHRASE.equals(q.kind)) return a.getString(R.string.ssh_wait_passphrase, q.identityName);
        if (SshPromptException.CHANGED_HOST.equals(q.kind)) return a.getString(R.string.ssh_wait_changed, q.hostPort);
        return a.getString(R.string.ssh_wait_unknown, q.hostPort);
    }

    /** The label of the button that answers the entry's question. */
    int answerLabel(DownloadTask t) {
        SshPromptException q = SshPromptException.fromToken(t.ask);
        if (q == null) return 0;
        if (SshPromptException.PASSPHRASE.equals(q.kind)) return R.string.ssh_btn_unlock;
        return SshPromptException.CHANGED_HOST.equals(q.kind) ? R.string.ssh_btn_replace : R.string.ssh_btn_trust;
    }

    /** Asks the entry's question; {@code retry} runs when the answer lets the download go on. */
    void answer(DownloadTask t, final Runnable retry) {
        final SshPromptException q = SshPromptException.fromToken(t.ask);
        if (q == null) return;
        if (SshPromptException.PASSPHRASE.equals(q.kind)) {
            askPassphrase(q, retry);
            return;
        }
        boolean changed = SshPromptException.CHANGED_HOST.equals(q.kind);
        String msg = changed
                ? a.getString(R.string.ssh_host_changed_msg, q.hostPort, q.oldKeyType, q.oldFingerprint, q.keyType, q.fingerprint)
                : a.getString(R.string.ssh_host_unknown_msg, q.hostPort, q.keyType, q.fingerprint);
        new AlertDialog.Builder(a)
                .setTitle(changed ? R.string.ssh_host_changed_title : R.string.ssh_host_unknown_title)
                .setMessage(msg)
                .setPositiveButton(changed ? R.string.ssh_btn_replace : R.string.ssh_btn_trust, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        try {
                            SshConfig.knownHosts().trust(q);
                            retry.run();
                        } catch (Exception e) {
                            Toast.makeText(a, String.valueOf(e.getMessage()), Toast.LENGTH_LONG).show();
                        }
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void askPassphrase(final SshPromptException q, final Runnable retry) {
        if (SshConfig.keys().isUnlocked(q.identityFingerprint)) { // answered for another entry meanwhile
            retry.run();
            return;
        }
        LinearLayout f = form();
        final EditText pass = field(f, R.string.ssh_key_passphrase_current, true);
        new AlertDialog.Builder(a)
                .setTitle(a.getString(R.string.ssh_passphrase_title, q.identityName))
                .setView(f)
                .setPositiveButton(R.string.ssh_btn_unlock, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        final String p = pass.getText().toString();
                        busy(new Work() {
                            void run() throws Exception {
                                SshConfig.keys().unlock(q.identityFingerprint, p);
                            }

                            void done(String error) {
                                if (error != null) {
                                    Toast.makeText(a, error, Toast.LENGTH_LONG).show();
                                    askPassphrase(q, retry);
                                } else {
                                    retry.run();
                                }
                            }
                        });
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}

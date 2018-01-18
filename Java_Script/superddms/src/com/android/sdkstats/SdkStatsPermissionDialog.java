/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.sdkstats;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.FontData;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.program.Program;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Link;
import org.eclipse.swt.widgets.Shell;

import java.io.IOException;

/**
 * Dialog to get user permission for ping service.
 */
public class SdkStatsPermissionDialog extends Dialog {
    /* Text strings displayed in the opt-out dialog. */
    private static final String HEADER_TEXT =
        "Thanks for using the Android SDK!";

    /** Used in the ADT welcome wizard as well. */
    public static final String NOTICE_TEXT =
        "We know you just want to get started but please read this first.";

    /** Used in the preference pane (PrefsDialog) as well. */
    public static final String BODY_TEXT =
        "By choosing to send certain usage statistics to Google, you can " +
        "help us improve the Android SDK. These usage statistics lets us " +
        "measure things like active usage of the SDK, and let us know things " +
        "like which versions of the SDK are in use and which tools are the " +
        "most popular with developers. This limited data is not associated " +
        "with personal information about you, and is examined on an aggregate " +
        "basis, and is maintained in accordance with the Google Privacy Policy.";

    /** Used in the ADT welcome wizard as well. */
    public static final String PRIVACY_POLICY_LINK_TEXT =
        "<a href=\"http://www.google.com/intl/en/privacy.html\">Google " +
        "Privacy Policy</a>";

    /** Used in the preference pane (PrefsDialog) as well. */
    public static final String CHECKBOX_TEXT =
        "Send usage statistics to Google.";

    /** Used in the ADT welcome wizard as well. */
    public static final String FOOTER_TEXT =
        "If you later decide to change this setting, you can do so in the" +
        "\"ddms\" tool under \"File\" > \"Preferences\" > \"Usage Stats\".";

    private static final String BUTTON_TEXT = "Proceed";

    /** List of Linux browser commands to try, in order (see openUrl). */
    private static final String[] LINUX_BROWSERS = new String[] {
        "firefox -remote openurl(%URL%,new-window)",  //$NON-NLS-1$ running FF
        "mozilla -remote openurl(%URL%,new-window)",  //$NON-NLS-1$ running Moz
        "firefox %URL%",                              //$NON-NLS-1$ new FF
        "mozilla %URL%",                              //$NON-NLS-1$ new Moz
        "kfmclient openURL %URL%",                    //$NON-NLS-1$ Konqueror
        "opera -newwindow %URL%",                     //$NON-NLS-1$ Opera
    };

    private static final boolean ALLOW_PING_DEFAULT = true;
    private boolean mAllowPing = ALLOW_PING_DEFAULT;

    public SdkStatsPermissionDialog(Shell parentShell) {
        super(parentShell);
        setBlockOnOpen(true);
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        createButton(parent, Window.OK, BUTTON_TEXT, true);
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        Composite composite = (Composite) super.createDialogArea(parent);
        composite.setLayout(new GridLayout(1, false));

        final Label title = new Label(composite, SWT.CENTER | SWT.WRAP);
        final FontData[] fontdata = title.getFont().getFontData();
        for (int i = 0; i < fontdata.length; i++) {
            fontdata[i].setHeight(fontdata[i].getHeight() * 4 / 3);
        }
        title.setFont(new Font(getShell().getDisplay(), fontdata));
        title.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        title.setText(HEADER_TEXT);

        final Label notice = new Label(composite, SWT.WRAP);
        notice.setFont(title.getFont());
        notice.setForeground(new Color(getShell().getDisplay(), 255, 0, 0));
        notice.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        notice.setText(NOTICE_TEXT);
        notice.pack();

        final Label bodyText = new Label(composite, SWT.WRAP);
        GridData gd = new GridData();
        gd.widthHint = notice.getSize().x;  // do not extend beyond the NOTICE text's width
        gd.grabExcessHorizontalSpace = true;
        bodyText.setLayoutData(gd);
        bodyText.setText(BODY_TEXT);

        final Link privacyLink = new Link(composite, SWT.NO_FOCUS);
        privacyLink.setText(PRIVACY_POLICY_LINK_TEXT);
        privacyLink.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                openUrl(event.text);
            }
        });

        final Button checkbox = new Button(composite, SWT.CHECK);
        checkbox.setSelection(ALLOW_PING_DEFAULT);
        checkbox.setText(CHECKBOX_TEXT);
        checkbox.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                mAllowPing = checkbox.getSelection();
            }
        });
        checkbox.setFocus();

        final Label footer = new Label(composite, SWT.WRAP);
        gd = new GridData();
        gd.widthHint = notice.getSize().x;
        gd.grabExcessHorizontalSpace = true;
        footer.setLayoutData(gd);
        footer.setText(FOOTER_TEXT);

        return composite;
    }

    /**
     * Open a URL in an external browser.
     * @param url to open - MUST be sanitized and properly formed!
     */
    public static void openUrl(final String url) {
        // TODO: consider using something like BrowserLauncher2
        // (http://browserlaunch2.sourceforge.net/) instead of these hacks.

        // SWT's Program.launch() should work on Mac, Windows, and GNOME
        // (because the OS shell knows how to launch a default browser).
        if (!Program.launch(url)) {
            // Must be Linux non-GNOME (or something else broke).
            // Try a few Linux browser commands in the background.
            new Thread() {
                @Override
                public void run() {
                    for (String cmd : LINUX_BROWSERS) {
                        cmd = cmd.replaceAll("%URL%", url);  //$NON-NLS-1$
                        try {
                            Process proc = Runtime.getRuntime().exec(cmd);
                            if (proc.waitFor() == 0) break;  // Success!
                        } catch (InterruptedException e) {
                            // Should never happen!
                            throw new RuntimeException(e);
                        } catch (IOException e) {
                            // Swallow the exception and try the next browser.
                        }
                    }

                    // TODO: Pop up some sort of error here?
                    // (We're in a new thread; can't use the existing Display.)
                }
            }.start();
        }
    }

    public boolean getPingUserPreference() {
        return mAllowPing;
    }
}

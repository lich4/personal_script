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
package com.android.ddmuilib.logcat;

import com.android.ddmlib.Log.LogLevel;

import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Dialog used to create or edit settings for a logcat filter.
 */
public final class LogCatFilterSettingsDialog extends TitleAreaDialog {
    private static final String TITLE = "Logcat Message Filter Settings";
    private static final String DEFAULT_MESSAGE =
            "Filter logcat messages by the source's tag, pid or minimum log level.\n"
            + "Empty fields will match all messages.";

    private String mFilterName;
    private String mTag;
    private String mText;
    private String mPid;
    private String mAppName;
    private String mLogLevel;

    private Text mFilterNameText;
    private Text mTagFilterText;
    private Text mTextFilterText;
    private Text mPidFilterText;
    private Text mAppNameFilterText;
    private Combo mLogLevelCombo;
    private Button mOkButton;

    /**
     * Construct the filter settings dialog with default values for all fields.
     * @param parentShell .
     */
    public LogCatFilterSettingsDialog(Shell parentShell) {
        super(parentShell);
        setDefaults("", "", "", "", "", LogLevel.VERBOSE);
    }

    /**
     * Set the default values to show when the dialog is opened.
     * @param filterName name for the filter.
     * @param tag value for filter by tag
     * @param text value for filter by text
     * @param pid value for filter by pid
     * @param appName value for filter by app name
     * @param level value for filter by log level
     */
    public void setDefaults(String filterName, String tag, String text, String pid, String appName,
            LogLevel level) {
        mFilterName = filterName;
        mTag = tag;
        mText = text;
        mPid = pid;
        mAppName = appName;
        mLogLevel = level.getStringValue();
    }

    @Override
    protected Control createDialogArea(Composite shell) {
        setTitle(TITLE);
        setMessage(DEFAULT_MESSAGE);

        Composite parent = (Composite) super.createDialogArea(shell);
        Composite c = new Composite(parent, SWT.BORDER);
        c.setLayout(new GridLayout(2, false));
        c.setLayoutData(new GridData(GridData.FILL_BOTH));

        createLabel(c, "Filter Name:");
        mFilterNameText = new Text(c, SWT.BORDER);
        mFilterNameText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        mFilterNameText.setText(mFilterName);

        createSeparator(c);

        createLabel(c, "by Log Tag:");
        mTagFilterText = new Text(c, SWT.BORDER);
        mTagFilterText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        mTagFilterText.setText(mTag);

        createLabel(c, "by Log Message:");
        mTextFilterText = new Text(c, SWT.BORDER);
        mTextFilterText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        mTextFilterText.setText(mText);

        createLabel(c, "by PID:");
        mPidFilterText = new Text(c, SWT.BORDER);
        mPidFilterText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        mPidFilterText.setText(mPid);

        createLabel(c, "by Application Name:");
        mAppNameFilterText = new Text(c, SWT.BORDER);
        mAppNameFilterText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        mAppNameFilterText.setText(mAppName);

        createLabel(c, "by Log Level:");
        mLogLevelCombo = new Combo(c, SWT.READ_ONLY | SWT.DROP_DOWN);
        mLogLevelCombo.setItems(getLogLevels().toArray(new String[0]));
        mLogLevelCombo.select(getLogLevels().indexOf(mLogLevel));

        /* call validateDialog() whenever user modifies any text field */
        ModifyListener m = new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent arg0) {
                DialogStatus status = validateDialog();
                mOkButton.setEnabled(status.valid);
                setErrorMessage(status.message);
            }
        };
        mFilterNameText.addModifyListener(m);
        mTagFilterText.addModifyListener(m);
        mTextFilterText.addModifyListener(m);
        mPidFilterText.addModifyListener(m);
        mAppNameFilterText.addModifyListener(m);

        return c;
    }


    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        super.createButtonsForButtonBar(parent);

        mOkButton = getButton(IDialogConstants.OK_ID);

        DialogStatus status = validateDialog();
        mOkButton.setEnabled(status.valid);
    }

    /**
     * A tuple that specifies whether the current state of the inputs
     * on the dialog is valid or not. If it is not valid, the message
     * field stores the reason why it isn't.
     */
    private static final class DialogStatus {
        final boolean valid;
        final String message;

        private DialogStatus(boolean isValid, String errMessage) {
            valid = isValid;
            message = errMessage;
        }
    }

    private DialogStatus validateDialog() {
        /* check that there is some name for the filter */
        if (mFilterNameText.getText().trim().equals("")) {
            return new DialogStatus(false,
                    "Please provide a name for this filter.");
        }

        /* if a pid is provided, it should be a +ve integer */
        String pidText = mPidFilterText.getText().trim();
        if (pidText.trim().length() > 0) {
            int pid = 0;
            try {
                pid = Integer.parseInt(pidText);
            } catch (NumberFormatException e) {
                return new DialogStatus(false,
                        "PID should be a positive integer.");
            }

            if (pid < 0) {
                return new DialogStatus(false,
                        "PID should be a positive integer.");
            }
        }

        /* tag field must use a valid regex pattern */
        String tagText = mTagFilterText.getText().trim();
        if (tagText.trim().length() > 0) {
            try {
                Pattern.compile(tagText);
            } catch (PatternSyntaxException e) {
                return new DialogStatus(false,
                        "Invalid regex used in tag field: " + e.getMessage());
            }
        }

        /* text field must use a valid regex pattern */
        String messageText = mTextFilterText.getText().trim();
        if (messageText.trim().length() > 0) {
            try {
                Pattern.compile(messageText);
            } catch (PatternSyntaxException e) {
                return new DialogStatus(false,
                        "Invalid regex used in text field: " + e.getMessage());
            }
        }

        /* app name field must use a valid regex pattern */
        String appNameText = mAppNameFilterText.getText().trim();
        if (appNameText.trim().length() > 0) {
            try {
                Pattern.compile(appNameText);
            } catch (PatternSyntaxException e) {
                return new DialogStatus(false,
                        "Invalid regex used in application name field: " + e.getMessage());
            }
        }

        return new DialogStatus(true, null);
    }

    private void createSeparator(Composite c) {
        Label l = new Label(c, SWT.SEPARATOR | SWT.HORIZONTAL);
        GridData gd = new GridData(GridData.FILL_HORIZONTAL);
        gd.horizontalSpan = 2;
        l.setLayoutData(gd);
    }

    private void createLabel(Composite c, String text) {
        Label l = new Label(c, SWT.NONE);
        l.setText(text);
        GridData gd = new GridData();
        gd.horizontalAlignment = SWT.RIGHT;
        l.setLayoutData(gd);
    }

    @Override
    protected void okPressed() {
        /* save values from the widgets before the shell is closed. */
        mFilterName = mFilterNameText.getText();
        mTag = mTagFilterText.getText();
        mText = mTextFilterText.getText();
        mLogLevel = mLogLevelCombo.getText();
        mPid = mPidFilterText.getText();
        mAppName = mAppNameFilterText.getText();

        super.okPressed();
    }

    /**
     * Obtain the name for this filter.
     * @return user provided filter name, maybe empty.
     */
    public String getFilterName() {
        return mFilterName;
    }

    /**
     * Obtain the tag regex to filter by.
     * @return user provided tag regex, maybe empty.
     */
    public String getTag() {
        return mTag;
    }

    /**
     * Obtain the text regex to filter by.
     * @return user provided tag regex, maybe empty.
     */
    public String getText() {
        return mText;
    }

    /**
     * Obtain user provided PID to filter by.
     * @return user provided pid, maybe empty.
     */
    public String getPid() {
        return mPid;
    }

    /**
     * Obtain user provided application name to filter by.
     * @return user provided app name regex, maybe empty
     */
    public String getAppName() {
        return mAppName;
    }

    /**
     * Obtain log level to filter by.
     * @return log level string.
     */
    public String getLogLevel() {
        return mLogLevel;
    }

    /**
     * Obtain the string representation of all supported log levels.
     * @return an array of strings, each representing a certain log level.
     */
    public static List<String> getLogLevels() {
        List<String> logLevels = new ArrayList<String>();

        for (LogLevel l : LogLevel.values()) {
            logLevels.add(l.getStringValue());
        }

        return logLevels;
    }
}

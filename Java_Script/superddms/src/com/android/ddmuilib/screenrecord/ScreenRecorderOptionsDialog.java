/*
 * Copyright (C) 2013 The Android Open Source Project
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

package com.android.ddmuilib.screenrecord;

import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

import java.io.File;
import java.util.Calendar;

public class ScreenRecorderOptionsDialog extends TitleAreaDialog {
    private static final int DEFAULT_BITRATE_MBPS = 4;

    private static String sLastSavedFolder = System.getProperty("user.home");
    private static String sLastFileName = suggestFileName();

    private static int sBitRateMbps = DEFAULT_BITRATE_MBPS;
    private static int sWidth = 0;
    private static int sHeight = 0;

    private Text mBitRateText;
    private Text mWidthText;
    private Text mHeightText;
    private Text mDestinationText;

    public ScreenRecorderOptionsDialog(Shell parentShell) {
        super(parentShell);
        setShellStyle(getShellStyle() | SWT.RESIZE);
    }

    @Override
    protected Control createDialogArea(Composite shell) {
        setTitle("Screen Recorder Options");
        setMessage("Provide screen recorder options. Leave empty to use defaults.");

        Composite parent = (Composite) super.createDialogArea(shell);
        Composite c = new Composite(parent, SWT.BORDER);
        c.setLayout(new GridLayout(3, false));
        c.setLayoutData(new GridData(GridData.FILL_BOTH));

        createLabel(c, "Bit Rate (in Mbps)");
        mBitRateText = new Text(c, SWT.BORDER);
        mBitRateText.setText(Integer.toString(sBitRateMbps));
        mBitRateText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        createLabel(c, ""); // empty label for 3rd column

        createLabel(c, "Video width (in px, defaults to screen width)");
        mWidthText = new Text(c, SWT.BORDER);
        mWidthText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        if (sWidth > 0) {
            mWidthText.setText(Integer.toString(sWidth));
        }
        createLabel(c, ""); // empty label for 3rd column

        createLabel(c, "Video height (in px, defaults to screen height)");
        mHeightText = new Text(c, SWT.BORDER);
        mHeightText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        if (sHeight > 0) {
            mHeightText.setText(Integer.toString(sHeight));
        }
        createLabel(c, ""); // empty label for 3rd column

        ModifyListener m = new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent modifyEvent) {
                validateAndUpdateState();
            }
        };
        mBitRateText.addModifyListener(m);
        mWidthText.addModifyListener(m);
        mHeightText.addModifyListener(m);

        createLabel(c, "Save Video as: ");
        mDestinationText = new Text(c, SWT.BORDER);
        mDestinationText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        mDestinationText.setText(getFilePath());

        Button browseButton = new Button(c, SWT.PUSH);
        browseButton.setText("Browse");
        browseButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent selectionEvent) {
                FileDialog dlg = new FileDialog(getShell(), SWT.SAVE);

                dlg.setText("Save Video...");
                dlg.setFileName(sLastFileName != null ? sLastFileName : suggestFileName());
                if (sLastSavedFolder != null) {
                    dlg.setFilterPath(sLastSavedFolder);
                }
                dlg.setFilterNames(new String[] { "MP4 files (*.mp4)" });
                dlg.setFilterExtensions(new String[] { "*.mp4" });

                String filePath = dlg.open();
                if (filePath != null) {
                    if (!filePath.endsWith(".mp4")) {
                        filePath += ".mp4";
                    }

                    mDestinationText.setText(filePath);
                    validateAndUpdateState();
                }
            }
        });

        return c;
    }

    private static String getFilePath() {
        return sLastSavedFolder + File.separatorChar + sLastFileName;
    }

    private static String suggestFileName() {
        Calendar now = Calendar.getInstance();
        return String.format("device-%tF-%tH%tM%tS.mp4", now, now, now, now);
    }

    private void createLabel(Composite c, String text) {
        Label l = new Label(c, SWT.NONE);
        l.setText(text);
        GridData gd = new GridData();
        gd.horizontalAlignment = SWT.RIGHT;
        l.setLayoutData(gd);
    }

    private void validateAndUpdateState() {
        int intValue;

        if ((intValue = validateInteger(mBitRateText.getText().trim(),
                "Bit Rate has to be an integer")) < 0) {
            return;
        }
        sBitRateMbps = intValue > 0 ? intValue : DEFAULT_BITRATE_MBPS;

        if ((intValue = validateInteger(mWidthText.getText().trim(),
                "Recorded video resolution width has to be a valid integer.")) < 0) {
            return;
        }
        if (intValue % 16 != 0) {
            setErrorMessage("Width must be a multiple of 16");
            setOkButtonEnabled(false);
            return;
        }
        sWidth = intValue;

        if ((intValue = validateInteger(mHeightText.getText().trim(),
                "Recorded video resolution height has to be a valid integer.")) < 0) {
            return;
        }
        if (intValue % 16 != 0) {
            setErrorMessage("Height must be a multiple of 16");
            setOkButtonEnabled(false);
            return;
        }
        sHeight = intValue;

        String filePath = mDestinationText.getText();
        File f = new File(filePath);
        if (!f.getParentFile().isDirectory()) {
            setErrorMessage("The path '" + f.getParentFile().getAbsolutePath() +
                    "' is not a valid directory.");
            setOkButtonEnabled(false);
            return;
        }
        sLastFileName = f.getName();
        sLastSavedFolder = f.getParentFile().getAbsolutePath();

        setErrorMessage(null);
        setOkButtonEnabled(true);
    }

    private int validateInteger(String s, String errorMessage) {
        if (!s.isEmpty()) {
            try {
                return Integer.parseInt(s);
            } catch (NumberFormatException e) {
                setErrorMessage(errorMessage);
                setOkButtonEnabled(false);
                return -1;
            }
        }

        return 0;
    }

    private void setOkButtonEnabled(boolean en) {
        getButton(IDialogConstants.OK_ID).setEnabled(en);
    }

    public int getBitRate() {
        return sBitRateMbps;
    }

    public int getWidth() {
        return sWidth;
    }

    public int getHeight() {
        return sHeight;
    }

    public File getDestination() {
        return new File(sLastSavedFolder, sLastFileName);
    }
}

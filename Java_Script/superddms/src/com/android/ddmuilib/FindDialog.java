/*
 * Copyright (C) 2012 The Android Open Source Project
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

package com.android.ddmuilib;


import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

/**
 * {@link FindDialog} provides a text box where users can enter text that should be
 * searched for in the target editor/view. The buttons "Find Previous" and "Find Next"
 * allow users to search forwards/backwards. This dialog simply provides a front end for the user
 * and the actual task of searching is delegated to the {@link IFindTarget}.
 */
public class FindDialog extends Dialog {
    private Label mStatusLabel;
    private Button mFindNext;
    private Button mFindPrevious;
    private final IFindTarget mTarget;
    private Text mSearchText;
    private String mPreviousSearchText;
    private final int mDefaultButtonId;

    /** Id of the "Find Next" button */
    public static final int FIND_NEXT_ID = IDialogConstants.CLIENT_ID;

    /** Id of the "Find Previous button */
    public static final int FIND_PREVIOUS_ID = IDialogConstants.CLIENT_ID + 1;

    public FindDialog(Shell shell, IFindTarget target) {
        this(shell, target, FIND_PREVIOUS_ID);
    }

    /**
     * Construct a find dialog.
     * @param shell shell to use
     * @param target delegate to be invoked on user action
     * @param defaultButtonId one of {@code #FIND_NEXT_ID} or {@code #FIND_PREVIOUS_ID}.
     */
    public FindDialog(Shell shell, IFindTarget target, int defaultButtonId) {
        super(shell);

        mTarget = target;
        mDefaultButtonId = defaultButtonId;

        setShellStyle((getShellStyle() & ~SWT.APPLICATION_MODAL) | SWT.MODELESS);
        setBlockOnOpen(true);
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        Composite panel = new Composite(parent, SWT.NONE);
        panel.setLayout(new GridLayout(2, false));
        panel.setLayoutData(new GridData(GridData.FILL_BOTH));

        Label lblMessage = new Label(panel, SWT.NONE);
        lblMessage.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, false, false, 1, 1));
        lblMessage.setText("Find:");

        mSearchText = new Text(panel, SWT.BORDER);
        mSearchText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        mSearchText.addModifyListener(new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent e) {
                boolean hasText = !mSearchText.getText().trim().isEmpty();
                mFindNext.setEnabled(hasText);
                mFindPrevious.setEnabled(hasText);
            }
        });

        mStatusLabel = new Label(panel, SWT.NONE);
        mStatusLabel.setForeground(getShell().getDisplay().getSystemColor(SWT.COLOR_DARK_RED));
        GridData gd = new GridData();
        gd.horizontalSpan = 2;
        gd.grabExcessHorizontalSpace = true;
        mStatusLabel.setLayoutData(gd);

        return panel;
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        createButton(parent, IDialogConstants.CLOSE_ID, IDialogConstants.CLOSE_LABEL, false);

        mFindNext = createButton(parent, FIND_NEXT_ID, "Find Next",
                mDefaultButtonId == FIND_NEXT_ID);
        mFindPrevious = createButton(parent, FIND_PREVIOUS_ID, "Find Previous",
                mDefaultButtonId != FIND_NEXT_ID);
        mFindNext.setEnabled(false);
        mFindPrevious.setEnabled(false);
    }

    @Override
    protected void buttonPressed(int buttonId) {
        if (buttonId == IDialogConstants.CLOSE_ID) {
            close();
            return;
        }

        if (buttonId == FIND_PREVIOUS_ID || buttonId == FIND_NEXT_ID) {
            if (mTarget != null) {
                String searchText = mSearchText.getText();
                boolean newSearch = !searchText.equals(mPreviousSearchText);
                mPreviousSearchText = searchText;
                boolean searchForward = buttonId == FIND_NEXT_ID;

                boolean hasMatches = mTarget.findAndSelect(searchText, newSearch, searchForward);
                if (!hasMatches) {
                    mStatusLabel.setText("String not found");
                    mStatusLabel.pack();
                } else {
                    mStatusLabel.setText("");
                }
            }
        }
    }
}

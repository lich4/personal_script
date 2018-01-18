/*
 * Copyright (C) 2007 The Android Open Source Project
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

package com.android.ddmuilib.explorer;

import com.android.ddmlib.AdbCommandRejectedException;
import com.android.ddmlib.DdmConstants;
import com.android.ddmlib.FileListingService;
import com.android.ddmlib.FileListingService.FileEntry;
import com.android.ddmlib.IDevice;
import com.android.ddmlib.IShellOutputReceiver;
import com.android.ddmlib.ShellCommandUnresponsiveException;
import com.android.ddmlib.SyncException;
import com.android.ddmlib.SyncService;
import com.android.ddmlib.SyncService.ISyncProgressMonitor;
import com.android.ddmlib.TimeoutException;
import com.android.ddmuilib.DdmUiPreferences;
import com.android.ddmuilib.ImageLoader;
import com.android.ddmuilib.Panel;
import com.android.ddmuilib.SyncProgressHelper;
import com.android.ddmuilib.SyncProgressHelper.SyncRunnable;
import com.android.ddmuilib.TableHelper;
import com.android.ddmuilib.actions.ICommonAction;
import com.android.ddmuilib.console.DdmConsole;

import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.jface.dialogs.ErrorDialog;
import org.eclipse.jface.dialogs.IInputValidator;
import org.eclipse.jface.dialogs.InputDialog;
import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.jface.viewers.DoubleClickEvent;
import org.eclipse.jface.viewers.IDoubleClickListener;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.viewers.ISelectionChangedListener;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.viewers.SelectionChangedEvent;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.jface.viewers.ViewerDropAdapter;
import org.eclipse.swt.SWT;
import org.eclipse.swt.dnd.DND;
import org.eclipse.swt.dnd.FileTransfer;
import org.eclipse.swt.dnd.Transfer;
import org.eclipse.swt.dnd.TransferData;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.DirectoryDialog;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.widgets.TreeItem;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Device filesystem explorer class.
 */
public class DeviceExplorer extends Panel {

    private final static String TRACE_KEY_EXT = ".key"; // $NON-NLS-1S
    private final static String TRACE_DATA_EXT = ".data"; // $NON-NLS-1S

    private static Pattern mKeyFilePattern = Pattern.compile(
            "(.+)\\" + TRACE_KEY_EXT); // $NON-NLS-1S
    private static Pattern mDataFilePattern = Pattern.compile(
            "(.+)\\" + TRACE_DATA_EXT); // $NON-NLS-1S

    public static String COLUMN_NAME = "android.explorer.name"; //$NON-NLS-1S
    public static String COLUMN_SIZE = "android.explorer.size"; //$NON-NLS-1S
    public static String COLUMN_DATE = "android.explorer.data"; //$NON-NLS-1S
    public static String COLUMN_TIME = "android.explorer.time"; //$NON-NLS-1S
    public static String COLUMN_PERMISSIONS = "android.explorer.permissions"; // $NON-NLS-1S
    public static String COLUMN_INFO = "android.explorer.info"; // $NON-NLS-1S

    private Composite mParent;
    private TreeViewer mTreeViewer;
    private Tree mTree;
    private DeviceContentProvider mContentProvider;

    private ICommonAction mPushAction;
    private ICommonAction mPullAction;
    private ICommonAction mDeleteAction;
    private ICommonAction mCreateNewFolderAction;

    private Image mFileImage;
    private Image mFolderImage;
    private Image mPackageImage;
    private Image mOtherImage;

    private IDevice mCurrentDevice;

    private String mDefaultSave;

    public DeviceExplorer() {
    }

    /**
     * Sets custom images for the device explorer. If none are set then defaults are used.
     * This can be useful to set platform-specific explorer icons.
     *
     * This should be called before {@link #createControl(Composite)}.
     *
     * @param fileImage the icon to represent a file.
     * @param folderImage the icon to represent a folder.
     * @param packageImage the icon to represent an apk.
     * @param otherImage the icon to represent other types of files.
     */
    public void setCustomImages(Image fileImage, Image folderImage, Image packageImage,
            Image otherImage) {
        mFileImage = fileImage;
        mFolderImage = folderImage;
        mPackageImage = packageImage;
        mOtherImage = otherImage;
    }

    /**
     * Sets the actions so that the device explorer can enable/disable them based on the current
     * selection
     * @param pushAction
     * @param pullAction
     * @param deleteAction
     * @param createNewFolderAction
     */
    public void setActions(ICommonAction pushAction, ICommonAction pullAction,
            ICommonAction deleteAction, ICommonAction createNewFolderAction) {
        mPushAction = pushAction;
        mPullAction = pullAction;
        mDeleteAction = deleteAction;
        mCreateNewFolderAction = createNewFolderAction;
    }

    /**
     * Creates a control capable of displaying some information.  This is
     * called once, when the application is initializing, from the UI thread.
     */
    @Override
    protected Control createControl(Composite parent) {
        mParent = parent;
        parent.setLayout(new FillLayout());

        ImageLoader loader = ImageLoader.getDdmUiLibLoader();
        if (mFileImage == null) {
            mFileImage = loader.loadImage("file.png", mParent.getDisplay());
        }
        if (mFolderImage == null) {
            mFolderImage = loader.loadImage("folder.png", mParent.getDisplay());
        }
        if (mPackageImage == null) {
            mPackageImage = loader.loadImage("android.png", mParent.getDisplay());
        }
        if (mOtherImage == null) {
            // TODO: find a default image for other.
        }

        mTree = new Tree(parent, SWT.MULTI | SWT.FULL_SELECTION | SWT.VIRTUAL);
        mTree.setHeaderVisible(true);

        IPreferenceStore store = DdmUiPreferences.getStore();

        // create columns
        TableHelper.createTreeColumn(mTree, "Name", SWT.LEFT,
                "0000drwxrwxrwx", COLUMN_NAME, store); //$NON-NLS-1$
        TableHelper.createTreeColumn(mTree, "Size", SWT.RIGHT,
                "000000", COLUMN_SIZE, store); //$NON-NLS-1$
        TableHelper.createTreeColumn(mTree, "Date", SWT.LEFT,
                "2007-08-14", COLUMN_DATE, store); //$NON-NLS-1$
        TableHelper.createTreeColumn(mTree, "Time", SWT.LEFT,
                "20:54", COLUMN_TIME, store); //$NON-NLS-1$
        TableHelper.createTreeColumn(mTree, "Permissions", SWT.LEFT,
                "drwxrwxrwx", COLUMN_PERMISSIONS, store); //$NON-NLS-1$
        TableHelper.createTreeColumn(mTree, "Info", SWT.LEFT,
                "drwxrwxrwx", COLUMN_INFO, store); //$NON-NLS-1$

        // create the jface wrapper
        mTreeViewer = new TreeViewer(mTree);

        // setup data provider
        mContentProvider = new DeviceContentProvider();
        mTreeViewer.setContentProvider(mContentProvider);
        mTreeViewer.setLabelProvider(new FileLabelProvider(mFileImage,
                mFolderImage, mPackageImage, mOtherImage));

        // setup a listener for selection
        mTreeViewer.addSelectionChangedListener(new ISelectionChangedListener() {
            @Override
            public void selectionChanged(SelectionChangedEvent event) {
                ISelection sel = event.getSelection();
                if (sel.isEmpty()) {
                    mPullAction.setEnabled(false);
                    mPushAction.setEnabled(false);
                    mDeleteAction.setEnabled(false);
                    mCreateNewFolderAction.setEnabled(false);
                    return;
                }
                if (sel instanceof IStructuredSelection) {
                    IStructuredSelection selection = (IStructuredSelection) sel;
                    Object element = selection.getFirstElement();
                    if (element == null)
                        return;
                    if (element instanceof FileEntry) {
                        mPullAction.setEnabled(true);
                        mPushAction.setEnabled(selection.size() == 1);
                        if (selection.size() == 1) {
                            FileEntry entry = (FileEntry) element;
                            setDeleteEnabledState(entry);
                            mCreateNewFolderAction.setEnabled(entry.isDirectory());
                        } else {
                            mDeleteAction.setEnabled(false);
                        }
                    }
                }
            }
        });

        // add support for double click
        mTreeViewer.addDoubleClickListener(new IDoubleClickListener() {
            @Override
            public void doubleClick(DoubleClickEvent event) {
                ISelection sel = event.getSelection();

                if (sel instanceof IStructuredSelection) {
                    IStructuredSelection selection = (IStructuredSelection) sel;

                    if (selection.size() == 1) {
                        FileEntry entry = (FileEntry)selection.getFirstElement();
                        String name = entry.getName();

                        FileEntry parentEntry = entry.getParent();

                        // can't really do anything with no parent
                        if (parentEntry == null) {
                            return;
                        }

                        // check this is a file like we want.
                        Matcher m = mKeyFilePattern.matcher(name);
                        if (m.matches()) {
                            // get the name w/o the extension
                            String baseName = m.group(1);

                            // add the data extension
                            String dataName = baseName + TRACE_DATA_EXT;

                            FileEntry dataEntry = parentEntry.findChild(dataName);

                            handleTraceDoubleClick(baseName, entry, dataEntry);

                        } else {
                            m = mDataFilePattern.matcher(name);
                            if (m.matches()) {
                                // get the name w/o the extension
                                String baseName = m.group(1);

                                // add the key extension
                                String keyName = baseName + TRACE_KEY_EXT;

                                FileEntry keyEntry = parentEntry.findChild(keyName);

                                handleTraceDoubleClick(baseName, keyEntry, entry);
                            }
                        }
                    }
                }
            }
        });

        // setup drop listener
        mTreeViewer.addDropSupport(DND.DROP_COPY | DND.DROP_MOVE,
                new Transfer[] { FileTransfer.getInstance() },
                new ViewerDropAdapter(mTreeViewer) {
            @Override
            public boolean performDrop(Object data) {
                // get the item on which we dropped the item(s)
                FileEntry target = (FileEntry)getCurrentTarget();

                // in case we drop at the same level as root
                if (target == null) {
                    return false;
                }

                // if the target is not a directory, we get the parent directory
                if (target.isDirectory() == false) {
                    target = target.getParent();
                }

                if (target == null) {
                    return false;
                }

                // get the list of files to drop
                String[] files = (String[])data;

                // do the drop
                pushFiles(files, target);

                // we need to finish with a refresh
                refresh(target);

                return true;
            }

            @Override
            public boolean validateDrop(Object target, int operation, TransferData transferType) {
                if (target == null) {
                    return false;
                }

                // convert to the real item
                FileEntry targetEntry = (FileEntry)target;

                // if the target is not a directory, we get the parent directory
                if (targetEntry.isDirectory() == false) {
                    target = targetEntry.getParent();
                }

                if (target == null) {
                    return false;
                }

                return true;
            }
        });

        // create and start the refresh thread
        new Thread("Device Ls refresher") {
            @Override
            public void run() {
                while (true) {
                    try {
                        sleep(FileListingService.REFRESH_RATE);
                    } catch (InterruptedException e) {
                        return;
                    }

                    if (mTree != null && mTree.isDisposed() == false) {
                        Display display = mTree.getDisplay();
                        if (display.isDisposed() == false) {
                            display.asyncExec(new Runnable() {
                                @Override
                                public void run() {
                                    if (mTree.isDisposed() == false) {
                                        mTreeViewer.refresh(true);
                                    }
                                }
                            });
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                }

            }
        }.start();

        return mTree;
    }

    @Override
    protected void postCreation() {

    }

    /**
     * Sets the focus to the proper control inside the panel.
     */
    @Override
    public void setFocus() {
        mTree.setFocus();
    }

    /**
     * Processes a double click on a trace file
     * @param baseName the base name of the 2 files.
     * @param keyEntry The FileEntry for the .key file.
     * @param dataEntry The FileEntry for the .data file.
     */
    private void handleTraceDoubleClick(String baseName, FileEntry keyEntry,
            FileEntry dataEntry) {
        // first we need to download the files.
        File keyFile;
        File dataFile;
        String path;
        try {
            // create a temp file for keyFile
            File f = File.createTempFile(baseName, DdmConstants.DOT_TRACE);
            f.delete();
            f.mkdir();

            path = f.getAbsolutePath();

            keyFile = new File(path + File.separator + keyEntry.getName());
            dataFile = new File(path + File.separator + dataEntry.getName());
        } catch (IOException e) {
            return;
        }

        // download the files
        try {
            SyncService sync = mCurrentDevice.getSyncService();
            if (sync != null) {
                ISyncProgressMonitor monitor = SyncService.getNullProgressMonitor();
                sync.pullFile(keyEntry, keyFile.getAbsolutePath(), monitor);
                sync.pullFile(dataEntry, dataFile.getAbsolutePath(), monitor);

                // now that we have the file, we need to launch traceview
                String[] command = new String[2];
                command[0] = DdmUiPreferences.getTraceview();
                command[1] = path + File.separator + baseName;

                try {
                    final Process p = Runtime.getRuntime().exec(command);

                    // create a thread for the output
                    new Thread("Traceview output") {
                        @Override
                        public void run() {
                            // create a buffer to read the stderr output
                            InputStreamReader is = new InputStreamReader(p.getErrorStream());
                            BufferedReader resultReader = new BufferedReader(is);

                            // read the lines as they come. if null is returned, it's
                            // because the process finished
                            try {
                                while (true) {
                                    String line = resultReader.readLine();
                                    if (line != null) {
                                        DdmConsole.printErrorToConsole("Traceview: " + line);
                                    } else {
                                        break;
                                    }
                                }
                                // get the return code from the process
                                p.waitFor();
                            } catch (IOException e) {
                            } catch (InterruptedException e) {

                            }
                        }
                    }.start();

                } catch (IOException e) {
                }
            }
        } catch (IOException e) {
            DdmConsole.printErrorToConsole(String.format(
                    "Failed to pull %1$s: %2$s", keyEntry.getName(), e.getMessage()));
            return;
        } catch (SyncException e) {
            if (e.wasCanceled() == false) {
                DdmConsole.printErrorToConsole(String.format(
                        "Failed to pull %1$s: %2$s", keyEntry.getName(), e.getMessage()));
                return;
            }
        } catch (TimeoutException e) {
            DdmConsole.printErrorToConsole(String.format(
                    "Failed to pull %1$s: timeout", keyEntry.getName()));
        } catch (AdbCommandRejectedException e) {
            DdmConsole.printErrorToConsole(String.format(
                    "Failed to pull %1$s: %2$s", keyEntry.getName(), e.getMessage()));
        }
    }

    /**
     * Pull the current selection on the local drive. This method displays
     * a dialog box to let the user select where to store the file(s) and
     * folder(s).
     */
    public void pullSelection() {
        // get the selection
        TreeItem[] items = mTree.getSelection();

        // name of the single file pull, or null if we're pulling a directory
        // or more than one object.
        String filePullName = null;
        FileEntry singleEntry = null;

        // are we pulling a single file?
        if (items.length == 1) {
            singleEntry = (FileEntry)items[0].getData();
            if (singleEntry.getType() == FileListingService.TYPE_FILE) {
                filePullName = singleEntry.getName();
            }
        }

        // where do we save by default?
        String defaultPath = mDefaultSave;
        if (defaultPath == null) {
            defaultPath = System.getProperty("user.home"); //$NON-NLS-1$
        }

        if (filePullName != null) {
            FileDialog fileDialog = new FileDialog(mParent.getShell(), SWT.SAVE);

            fileDialog.setText("Get Device File");
            fileDialog.setFileName(filePullName);
            fileDialog.setFilterPath(defaultPath);

            String fileName = fileDialog.open();
            if (fileName != null) {
                mDefaultSave = fileDialog.getFilterPath();

                pullFile(singleEntry, fileName);
            }
        } else {
            DirectoryDialog directoryDialog = new DirectoryDialog(mParent.getShell(), SWT.SAVE);

            directoryDialog.setText("Get Device Files/Folders");
            directoryDialog.setFilterPath(defaultPath);

            String directoryName = directoryDialog.open();
            if (directoryName != null) {
                pullSelection(items, directoryName);
            }
        }
    }

    /**
     * Push new file(s) and folder(s) into the current selection. Current
     * selection must be single item. If the current selection is not a
     * directory, the parent directory is used.
     * This method displays a dialog to let the user choose file to push to
     * the device.
     */
    public void pushIntoSelection() {
        // get the name of the object we're going to pull
        TreeItem[] items = mTree.getSelection();

        if (items.length == 0) {
            return;
        }

        FileDialog dlg = new FileDialog(mParent.getShell(), SWT.OPEN);
        String fileName;

        dlg.setText("Put File on Device");

        // There should be only one.
        FileEntry entry = (FileEntry)items[0].getData();
        dlg.setFileName(entry.getName());

        String defaultPath = mDefaultSave;
        if (defaultPath == null) {
            defaultPath = System.getProperty("user.home"); //$NON-NLS-1$
        }
        dlg.setFilterPath(defaultPath);

        fileName = dlg.open();
        if (fileName != null) {
            mDefaultSave = dlg.getFilterPath();

            // we need to figure out the remote path based on the current selection type.
            String remotePath;
            FileEntry toRefresh = entry;
            if (entry.isDirectory()) {
                remotePath = entry.getFullPath();
            } else {
                toRefresh = entry.getParent();
                remotePath = toRefresh.getFullPath();
            }

            pushFile(fileName, remotePath);
            mTreeViewer.refresh(toRefresh);
        }
    }

    public void deleteSelection() {
        // get the name of the object we're going to pull
        TreeItem[] items = mTree.getSelection();

        if (items.length != 1) {
            return;
        }

        FileEntry entry = (FileEntry)items[0].getData();
        final FileEntry parentEntry = entry.getParent();

        // create the delete command
        String command = "rm " + entry.getFullEscapedPath(); //$NON-NLS-1$

        try {
            mCurrentDevice.executeShellCommand(command, new IShellOutputReceiver() {
                @Override
                public void addOutput(byte[] data, int offset, int length) {
                    // pass
                    // TODO get output to display errors if any.
                }

                @Override
                public void flush() {
                    mTreeViewer.refresh(parentEntry);
                }

                @Override
                public boolean isCancelled() {
                    return false;
                }
            });
        } catch (IOException e) {
            // adb failed somehow, we do nothing. We should be displaying the error from the output
            // of the shell command.
        } catch (TimeoutException e) {
            // adb failed somehow, we do nothing. We should be displaying the error from the output
            // of the shell command.
        } catch (AdbCommandRejectedException e) {
            // adb failed somehow, we do nothing. We should be displaying the error from the output
            // of the shell command.
        } catch (ShellCommandUnresponsiveException e) {
            // adb failed somehow, we do nothing. We should be displaying the error from the output
            // of the shell command.
        }

    }

    public void createNewFolderInSelection() {
        TreeItem[] items = mTree.getSelection();

        if (items.length != 1) {
            return;
        }

        final FileEntry entry = (FileEntry) items[0].getData();

        if (entry.isDirectory()) {
            InputDialog inputDialog = new InputDialog(mTree.getShell(), "New Folder",
                    "Please enter the new folder name", "New Folder", new IInputValidator() {
                        @Override
                        public String isValid(String newText) {
                            if ((newText != null) && (newText.length() > 0)
                                    && (newText.trim().length() > 0)
                                    && (newText.indexOf('/') == -1)
                                    && (newText.indexOf('\\') == -1)) {
                                return null;
                            } else {
                                return "Invalid name";
                            }
                        }
                    });
            inputDialog.open();
            String value = inputDialog.getValue();

            if (value != null) {
                // create the mkdir command
                String command = "mkdir " + entry.getFullEscapedPath() //$NON-NLS-1$
                        + FileListingService.FILE_SEPARATOR + FileEntry.escape(value);

                try {
                    mCurrentDevice.executeShellCommand(command, new IShellOutputReceiver() {

                        @Override
                        public boolean isCancelled() {
                            return false;
                        }

                        @Override
                        public void flush() {
                            mTreeViewer.refresh(entry);
                        }

                        @Override
                        public void addOutput(byte[] data, int offset, int length) {
                            String errorMessage;
                            if (data != null) {
                                errorMessage = new String(data);
                            } else {
                                errorMessage = "";
                            }
                            Status status = new Status(IStatus.ERROR,
                                    "DeviceExplorer", 0, errorMessage, null); //$NON-NLS-1$
                            ErrorDialog.openError(mTree.getShell(), "New Folder Error",
                                    "New Folder Error", status);
                        }
                    });
                } catch (TimeoutException e) {
                    // adb failed somehow, we do nothing. We should be
                    // displaying the error from the output of the shell
                    // command.
                } catch (AdbCommandRejectedException e) {
                    // adb failed somehow, we do nothing. We should be
                    // displaying the error from the output of the shell
                    // command.
                } catch (ShellCommandUnresponsiveException e) {
                    // adb failed somehow, we do nothing. We should be
                    // displaying the error from the output of the shell
                    // command.
                } catch (IOException e) {
                    // adb failed somehow, we do nothing. We should be
                    // displaying the error from the output of the shell
                    // command.
                }
            }
        }
    }

    /**
     * Force a full refresh of the explorer.
     */
    public void refresh() {
        mTreeViewer.refresh(true);
    }

    /**
     * Sets the new device to explorer
     */
    public void switchDevice(final IDevice device) {
        if (device != mCurrentDevice) {
            mCurrentDevice = device;
            // now we change the input. but we need to do that in the
            // ui thread.
            if (mTree.isDisposed() == false) {
                Display d = mTree.getDisplay();
                d.asyncExec(new Runnable() {
                    @Override
                    public void run() {
                        if (mTree.isDisposed() == false) {
                            // new service
                            if (mCurrentDevice != null) {
                                FileListingService fls = mCurrentDevice.getFileListingService();
                                mContentProvider.setListingService(fls);
                                mTreeViewer.setInput(fls.getRoot());
                            }
                        }
                    }
                });
            }
        }
    }

    /**
     * Refresh an entry from a non ui thread.
     * @param entry the entry to refresh.
     */
    private void refresh(final FileEntry entry) {
        Display d = mTreeViewer.getTree().getDisplay();
        d.asyncExec(new Runnable() {
            @Override
            public void run() {
                mTreeViewer.refresh(entry);
            }
        });
    }

    /**
     * Pulls the selection from a device.
     * @param items the tree selection the remote file on the device
     * @param localDirector the local directory in which to save the files.
     */
    private void pullSelection(TreeItem[] items, final String localDirectory) {
        try {
            final SyncService sync = mCurrentDevice.getSyncService();
            if (sync != null) {
                // make a list of the FileEntry.
                ArrayList<FileEntry> entries = new ArrayList<FileEntry>();
                for (TreeItem item : items) {
                    Object data = item.getData();
                    if (data instanceof FileEntry) {
                        entries.add((FileEntry)data);
                    }
                }
                final FileEntry[] entryArray = entries.toArray(
                        new FileEntry[entries.size()]);

                SyncProgressHelper.run(new SyncRunnable() {
                    @Override
                    public void run(ISyncProgressMonitor monitor)
                            throws SyncException, IOException, TimeoutException {
                        sync.pull(entryArray, localDirectory, monitor);
                    }

                    @Override
                    public void close() {
                        sync.close();
                    }
                }, "Pulling file(s) from the device", mParent.getShell());
            }
        } catch (SyncException e) {
            if (e.wasCanceled() == false) {
                DdmConsole.printErrorToConsole(String.format(
                        "Failed to pull selection: %1$s", e.getMessage()));
            }
        } catch (Exception e) {
            DdmConsole.printErrorToConsole( "Failed to pull selection");
            DdmConsole.printErrorToConsole(e.getMessage());
        }
    }

    /**
     * Pulls a file from a device.
     * @param remote the remote file on the device
     * @param local the destination filepath
     */
    private void pullFile(final FileEntry remote, final String local) {
        try {
            final SyncService sync = mCurrentDevice.getSyncService();
            if (sync != null) {
                SyncProgressHelper.run(new SyncRunnable() {
                        @Override
                        public void run(ISyncProgressMonitor monitor)
                                throws SyncException, IOException, TimeoutException {
                            sync.pullFile(remote, local, monitor);
                        }

                        @Override
                        public void close() {
                            sync.close();
                        }
                    }, String.format("Pulling %1$s from the device", remote.getName()),
                    mParent.getShell());
            }
        } catch (SyncException e) {
            if (e.wasCanceled() == false) {
                DdmConsole.printErrorToConsole(String.format(
                        "Failed to pull selection: %1$s", e.getMessage()));
            }
        } catch (Exception e) {
            DdmConsole.printErrorToConsole( "Failed to pull selection");
            DdmConsole.printErrorToConsole(e.getMessage());
        }
    }

    /**
     * Pushes several files and directory into a remote directory.
     * @param localFiles
     * @param remoteDirectory
     */
    private void pushFiles(final String[] localFiles, final FileEntry remoteDirectory) {
        try {
            final SyncService sync = mCurrentDevice.getSyncService();
            if (sync != null) {
                SyncProgressHelper.run(new SyncRunnable() {
                        @Override
                        public void run(ISyncProgressMonitor monitor)
                                throws SyncException, IOException, TimeoutException {
                            sync.push(localFiles, remoteDirectory, monitor);
                        }

                        @Override
                        public void close() {
                            sync.close();
                        }
                    }, "Pushing file(s) to the device", mParent.getShell());
            }
        } catch (SyncException e) {
            if (e.wasCanceled() == false) {
                DdmConsole.printErrorToConsole(String.format(
                        "Failed to push selection: %1$s", e.getMessage()));
            }
        } catch (Exception e) {
            DdmConsole.printErrorToConsole("Failed to push the items");
            DdmConsole.printErrorToConsole(e.getMessage());
        }
    }

    /**
     * Pushes a file on a device.
     * @param local the local filepath of the file to push
     * @param remoteDirectory the remote destination directory on the device
     */
    private void pushFile(final String local, final String remoteDirectory) {
        try {
            final SyncService sync = mCurrentDevice.getSyncService();
            if (sync != null) {
                // get the file name
                String[] segs = local.split(Pattern.quote(File.separator));
                String name = segs[segs.length-1];
                final String remoteFile = remoteDirectory + FileListingService.FILE_SEPARATOR
                        + name;

                SyncProgressHelper.run(new SyncRunnable() {
                        @Override
                        public void run(ISyncProgressMonitor monitor)
                                throws SyncException, IOException, TimeoutException {
                            sync.pushFile(local, remoteFile, monitor);
                        }

                        @Override
                        public void close() {
                            sync.close();
                        }
                    }, String.format("Pushing %1$s to the device.", name), mParent.getShell());
            }
        } catch (SyncException e) {
            if (e.wasCanceled() == false) {
                DdmConsole.printErrorToConsole(String.format(
                        "Failed to push selection: %1$s", e.getMessage()));
            }
        } catch (Exception e) {
            DdmConsole.printErrorToConsole("Failed to push the item(s).");
            DdmConsole.printErrorToConsole(e.getMessage());
        }
    }

    /**
     * Sets the enabled state based on a FileEntry properties
     * @param element The selected FileEntry
     */
    protected void setDeleteEnabledState(FileEntry element) {
        mDeleteAction.setEnabled(element.getType() == FileListingService.TYPE_FILE);
    }
}

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

package com.android.ddmuilib.heap;

import com.android.ddmlib.Client;
import com.android.ddmlib.Log;
import com.android.ddmlib.NativeAllocationInfo;
import com.android.ddmlib.NativeLibraryMapInfo;
import com.android.ddmlib.NativeStackCallInfo;
import com.android.ddmuilib.Addr2Line;
import com.android.ddmuilib.BaseHeapPanel;
import com.android.ddmuilib.ITableFocusListener;
import com.android.ddmuilib.ITableFocusListener.IFocusedTableActivator;
import com.android.ddmuilib.ImageLoader;
import com.android.ddmuilib.TableHelper;

import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.dnd.Clipboard;
import org.eclipse.swt.dnd.TextTransfer;
import org.eclipse.swt.dnd.Transfer;
import org.eclipse.swt.events.FocusEvent;
import org.eclipse.swt.events.FocusListener;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.FormAttachment;
import org.eclipse.swt.layout.FormData;
import org.eclipse.swt.layout.FormLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Sash;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.widgets.ToolBar;
import org.eclipse.swt.widgets.ToolItem;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.widgets.TreeItem;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Panel to display native heap information. */
public class NativeHeapPanel extends BaseHeapPanel {
    private static final boolean USE_OLD_RESOLVER;
    static {
        String useOldResolver = System.getenv("ANDROID_DDMS_OLD_SYMRESOLVER");
        USE_OLD_RESOLVER = useOldResolver != null && useOldResolver.equalsIgnoreCase("true");
    }
    private final int MAX_DISPLAYED_ERROR_ITEMS = 5;

    private static final String TOOLTIP_EXPORT_DATA = "Export Heap Data";
    private static final String TOOLTIP_ZYGOTE_ALLOCATIONS = "Show Zygote Allocations";
    private static final String TOOLTIP_DIFFS_ONLY = "Only show new allocations not present in previous snapshot";
    private static final String TOOLTIP_GROUPBY = "Group allocations by library.";

    private static final String EXPORT_DATA_IMAGE = "save.png";
    private static final String ZYGOTE_IMAGE = "zygote.png";
    private static final String DIFFS_ONLY_IMAGE = "diff.png";
    private static final String GROUPBY_IMAGE = "groupby.png";

    private static final String SNAPSHOT_HEAP_BUTTON_TEXT = "Snapshot Current Native Heap Usage";
    private static final String LOAD_HEAP_DATA_BUTTON_TEXT = "Import Heap Data";
    private static final String SYMBOL_SEARCH_PATH_LABEL_TEXT = "Symbol Search Path:";
    private static final String SYMBOL_SEARCH_PATH_TEXT_MESSAGE =
            "List of colon separated paths to search for symbol debug information. See tooltip for examples.";
    private static final String SYMBOL_SEARCH_PATH_TOOLTIP_TEXT =
            "Colon separated paths that contain unstripped libraries with debug symbols.\n"
                    + "e.g.: <android-src>/out/target/product/generic/symbols/system/lib:/path/to/my/app/obj/local/armeabi";

    private static final String PREFS_SHOW_DIFFS_ONLY = "nativeheap.show.diffs.only";
    private static final String PREFS_SHOW_ZYGOTE_ALLOCATIONS = "nativeheap.show.zygote";
    private static final String PREFS_GROUP_BY_LIBRARY = "nativeheap.grouby.library";
    private static final String PREFS_SYMBOL_SEARCH_PATH = "nativeheap.search.path";
    private static final String PREFS_SASH_HEIGHT_PERCENT = "nativeheap.sash.percent";
    private static final String PREFS_LAST_IMPORTED_HEAPPATH = "nativeheap.last.import.path";
    private IPreferenceStore mPrefStore;

    private List<NativeHeapSnapshot> mNativeHeapSnapshots;

    // Maintain the differences between a snapshot and its predecessor.
    // mDiffSnapshots[i] = mNativeHeapSnapshots[i] - mNativeHeapSnapshots[i-1]
    // The zeroth entry is null since there is no predecessor.
    // The list is filled lazily on demand.
    private List<NativeHeapSnapshot> mDiffSnapshots;

    private Map<Integer, List<NativeHeapSnapshot>> mImportedSnapshotsPerPid;

    private Button mSnapshotHeapButton;
    private Button mLoadHeapDataButton;
    private Text mSymbolSearchPathText;
    private Combo mSnapshotIndexCombo;
    private Label mMemoryAllocatedText;

    private TreeViewer mDetailsTreeViewer;
    private TreeViewer mStackTraceTreeViewer;
    private NativeHeapProviderByAllocations mContentProviderByAllocations;
    private NativeHeapProviderByLibrary mContentProviderByLibrary;
    private NativeHeapLabelProvider mDetailsTreeLabelProvider;

    private ToolItem mGroupByButton;
    private ToolItem mDiffsOnlyButton;
    private ToolItem mShowZygoteAllocationsButton;
    private ToolItem mExportHeapDataButton;

    public NativeHeapPanel(IPreferenceStore prefStore) {
        mPrefStore = prefStore;
        mPrefStore.setDefault(PREFS_SASH_HEIGHT_PERCENT, 75);
        mPrefStore.setDefault(PREFS_SYMBOL_SEARCH_PATH, "");
        mPrefStore.setDefault(PREFS_GROUP_BY_LIBRARY, false);
        mPrefStore.setDefault(PREFS_SHOW_ZYGOTE_ALLOCATIONS, true);
        mPrefStore.setDefault(PREFS_SHOW_DIFFS_ONLY, false);

        mNativeHeapSnapshots = new ArrayList<NativeHeapSnapshot>();
        mDiffSnapshots = new ArrayList<NativeHeapSnapshot>();
        mImportedSnapshotsPerPid = new HashMap<Integer, List<NativeHeapSnapshot>>();
    }

    /** {@inheritDoc} */
    @Override
    public void clientChanged(final Client client, int changeMask) {
        if (client != getCurrentClient()) {
            return;
        }

        if ((changeMask & Client.CHANGE_NATIVE_HEAP_DATA) != Client.CHANGE_NATIVE_HEAP_DATA) {
            return;
        }

        List<NativeAllocationInfo> allocations = client.getClientData().getNativeAllocationList();
        if (allocations.size() == 0) {
            return;
        }

        // We need to clone this list since getClientData().getNativeAllocationList() clobbers
        // the list on future updates
        final List<NativeAllocationInfo> nativeAllocations = shallowCloneList(allocations);

        addNativeHeapSnapshot(new NativeHeapSnapshot(nativeAllocations));
        updateDisplay();

        // Attempt to resolve symbols in a separate thread.
        // The UI should be refreshed once the symbols have been resolved.
        if (USE_OLD_RESOLVER) {
            Thread t = new Thread(new SymbolResolverTask(nativeAllocations,
                    client.getClientData().getMappedNativeLibraries()));
            t.setName("Address to Symbol Resolver");
            t.start();
        } else {
            Display.getDefault().asyncExec(new Runnable() {
                @Override
                public void run() {
                    resolveSymbols();
                    mDetailsTreeViewer.refresh();
                    mStackTraceTreeViewer.refresh();
                }

                public void resolveSymbols() {
                    Shell shell = Display.getDefault().getActiveShell();
                    ProgressMonitorDialog d = new ProgressMonitorDialog(shell);

                    NativeSymbolResolverTask resolver = new NativeSymbolResolverTask(
                            nativeAllocations,
                            client.getClientData().getMappedNativeLibraries(),
                            mSymbolSearchPathText.getText(),
                            client.getClientData().getAbi());

                    try {
                        d.run(true, true, resolver);
                    } catch (InvocationTargetException e) {
                        MessageDialog.openError(shell,
                                "Error Resolving Symbols",
                                e.getCause().getMessage());
                        return;
                    } catch (InterruptedException e) {
                        return;
                    }

                    MessageDialog.openInformation(shell, "Symbol Resolution Status",
                            getResolutionStatusMessage(resolver));
                }
            });
        }
    }

    private String getResolutionStatusMessage(NativeSymbolResolverTask resolver) {
        StringBuilder sb = new StringBuilder();
        sb.append("Symbol Resolution Complete.\n\n");

        // show addresses that were not mapped
        Set<Long> unmappedAddresses = resolver.getUnmappedAddresses();
        if (unmappedAddresses.size() > 0) {
            sb.append(String.format("Unmapped addresses (%d): ",
                    unmappedAddresses.size()));
            sb.append(getSampleForDisplay(unmappedAddresses));
            sb.append('\n');
        }

        // show libraries that were not present on disk
        Set<String> notFoundLibraries = resolver.getNotFoundLibraries();
        if (notFoundLibraries.size() > 0) {
            sb.append(String.format("Libraries not found on disk (%d): ",
                    notFoundLibraries.size()));
            sb.append(getSampleForDisplay(notFoundLibraries));
            sb.append('\n');
        }

        // show addresses that were mapped but not resolved
        Set<Long> unresolvableAddresses = resolver.getUnresolvableAddresses();
        if (unresolvableAddresses.size() > 0) {
            sb.append(String.format("Unresolved addresses (%d): ",
                    unresolvableAddresses.size()));
            sb.append(getSampleForDisplay(unresolvableAddresses));
            sb.append('\n');
        }

        if (resolver.getAddr2LineErrorMessage() != null) {
            sb.append("Error launching addr2line: ");
            sb.append(resolver.getAddr2LineErrorMessage());
        }

        return sb.toString();
    }

    /**
     * Get the string representation for a collection of items.
     * If there are more items than {@link #MAX_DISPLAYED_ERROR_ITEMS}, then only the first
     * {@link #MAX_DISPLAYED_ERROR_ITEMS} items are taken into account,
     * and an ellipsis is added at the end.
     */
    private String getSampleForDisplay(Collection<?> items) {
        StringBuilder sb = new StringBuilder();

        int c = 1;
        Iterator<?> it = items.iterator();
        while (it.hasNext()) {
            Object item = it.next();
            if (item instanceof Long) {
                sb.append(String.format("0x%x", item));
            } else {
                sb.append(item);
            }

            if (c == MAX_DISPLAYED_ERROR_ITEMS && it.hasNext()) {
                sb.append(", ...");
                break;
            } else if (it.hasNext()) {
                sb.append(", ");
            }

            c++;
        }
        return sb.toString();
    }

    private void addNativeHeapSnapshot(NativeHeapSnapshot snapshot) {
        mNativeHeapSnapshots.add(snapshot);

        // The diff snapshots are filled in lazily on demand.
        // But the list needs to be the same size as mNativeHeapSnapshots, so we add a null.
        mDiffSnapshots.add(null);
    }

    private List<NativeAllocationInfo> shallowCloneList(List<NativeAllocationInfo> allocations) {
        List<NativeAllocationInfo> clonedList =
                new ArrayList<NativeAllocationInfo>(allocations.size());

        for (NativeAllocationInfo i : allocations) {
            clonedList.add(i);
        }

        return clonedList;
    }

    @Override
    public void deviceSelected() {
        // pass
    }

    @Override
    public void clientSelected() {
        Client c = getCurrentClient();

        if (c == null) {
            // if there is no client selected, then we disable the buttons but leave the
            // display as is so that whatever snapshots are displayed continue to stay
            // visible to the user.
            mSnapshotHeapButton.setEnabled(false);
            mLoadHeapDataButton.setEnabled(false);
            return;
        }

        mNativeHeapSnapshots = new ArrayList<NativeHeapSnapshot>();
        mDiffSnapshots = new ArrayList<NativeHeapSnapshot>();

        mSnapshotHeapButton.setEnabled(true);
        mLoadHeapDataButton.setEnabled(true);

        List<NativeHeapSnapshot> importedSnapshots = mImportedSnapshotsPerPid.get(
                c.getClientData().getPid());
        if (importedSnapshots != null) {
            for (NativeHeapSnapshot n : importedSnapshots) {
                addNativeHeapSnapshot(n);
            }
        }

        List<NativeAllocationInfo> allocations = c.getClientData().getNativeAllocationList();
        allocations = shallowCloneList(allocations);

        if (allocations.size() > 0) {
            addNativeHeapSnapshot(new NativeHeapSnapshot(allocations));
        }

        updateDisplay();
    }

    private void updateDisplay() {
        Display.getDefault().syncExec(new Runnable() {
            @Override
            public void run() {
                updateSnapshotIndexCombo();
                updateToolbars();

                int lastSnapshotIndex = mNativeHeapSnapshots.size() - 1;
                displaySnapshot(lastSnapshotIndex);
                displayStackTraceForSelection();
            }
        });
    }

    private void displaySelectedSnapshot() {
        Display.getDefault().syncExec(new Runnable() {
            @Override
            public void run() {
                int idx = mSnapshotIndexCombo.getSelectionIndex();
                displaySnapshot(idx);
            }
        });
    }

    private void displaySnapshot(int index) {
        if (index < 0 || mNativeHeapSnapshots.size() == 0) {
            mDetailsTreeViewer.setInput(null);
            mMemoryAllocatedText.setText("");
            return;
        }

        assert index < mNativeHeapSnapshots.size() : "Invalid snapshot index";

        NativeHeapSnapshot snapshot = mNativeHeapSnapshots.get(index);
        if (mDiffsOnlyButton.getSelection() && index > 0) {
            snapshot = getDiffSnapshot(index);
        }

        mMemoryAllocatedText.setText(snapshot.getFormattedMemorySize());
        mMemoryAllocatedText.pack();

        mDetailsTreeLabelProvider.setTotalSize(snapshot.getTotalSize());
        mDetailsTreeViewer.setInput(snapshot);
        mDetailsTreeViewer.refresh();
    }

    /** Obtain the diff of snapshot[index] & snapshot[index-1] */
    private NativeHeapSnapshot getDiffSnapshot(int index) {
        // if it was already computed, simply return that
        NativeHeapSnapshot diffSnapshot = mDiffSnapshots.get(index);
        if (diffSnapshot != null) {
            return diffSnapshot;
        }

        // compute the diff
        NativeHeapSnapshot cur = mNativeHeapSnapshots.get(index);
        NativeHeapSnapshot prev = mNativeHeapSnapshots.get(index - 1);
        diffSnapshot = new NativeHeapDiffSnapshot(cur, prev);

        // cache for future use
        mDiffSnapshots.set(index, diffSnapshot);

        return diffSnapshot;
    }

    private void updateDisplayGrouping() {
        boolean groupByLibrary = mGroupByButton.getSelection();
        mPrefStore.setValue(PREFS_GROUP_BY_LIBRARY, groupByLibrary);

        if (groupByLibrary) {
            mDetailsTreeViewer.setContentProvider(mContentProviderByLibrary);
        } else {
            mDetailsTreeViewer.setContentProvider(mContentProviderByAllocations);
        }
    }

    private void updateDisplayForZygotes() {
        boolean displayZygoteMemory = mShowZygoteAllocationsButton.getSelection();
        mPrefStore.setValue(PREFS_SHOW_ZYGOTE_ALLOCATIONS, displayZygoteMemory);

        // inform the content providers of the zygote display setting
        mContentProviderByLibrary.displayZygoteMemory(displayZygoteMemory);
        mContentProviderByAllocations.displayZygoteMemory(displayZygoteMemory);

        // refresh the UI
        mDetailsTreeViewer.refresh();
    }

    private void updateSnapshotIndexCombo() {
        List<String> items = new ArrayList<String>();

        int numSnapshots = mNativeHeapSnapshots.size();
        for (int i = 0; i < numSnapshots; i++) {
            // offset indices by 1 so that users see index starting at 1 rather than 0
            items.add("Snapshot " + (i + 1));
        }

        mSnapshotIndexCombo.setItems(items.toArray(new String[items.size()]));

        if (numSnapshots > 0) {
            mSnapshotIndexCombo.setEnabled(true);
            mSnapshotIndexCombo.select(numSnapshots - 1);
        } else {
            mSnapshotIndexCombo.setEnabled(false);
        }
    }

    private void updateToolbars() {
        int numSnapshots = mNativeHeapSnapshots.size();
        mExportHeapDataButton.setEnabled(numSnapshots > 0);
    }

    @Override
    protected Control createControl(Composite parent) {
        Composite c = new Composite(parent, SWT.NONE);
        c.setLayout(new GridLayout(1, false));
        c.setLayoutData(new GridData(GridData.FILL_BOTH));

        createControlsSection(c);
        createDetailsSection(c);

        // Initialize widget state based on whether a client
        // is selected or not.
        clientSelected();

        return c;
    }

    private void createControlsSection(Composite parent) {
        Composite c = new Composite(parent, SWT.NONE);
        c.setLayout(new GridLayout(3, false));
        c.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        createGetHeapDataSection(c);

        Label l = new Label(c, SWT.SEPARATOR | SWT.VERTICAL);
        l.setLayoutData(new GridData(GridData.FILL_VERTICAL));

        createDisplaySection(c);
    }

    private void createGetHeapDataSection(Composite parent) {
        Composite c = new Composite(parent, SWT.NONE);
        c.setLayout(new GridLayout(1, false));

        createTakeHeapSnapshotButton(c);

        Label l = new Label(c, SWT.SEPARATOR | SWT.HORIZONTAL);
        l.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        createLoadHeapDataButton(c);
    }

    private void createTakeHeapSnapshotButton(Composite parent) {
        mSnapshotHeapButton = new Button(parent, SWT.BORDER | SWT.PUSH);
        mSnapshotHeapButton.setText(SNAPSHOT_HEAP_BUTTON_TEXT);
        mSnapshotHeapButton.setLayoutData(new GridData());

        // disable by default, enabled only when a client is selected
        mSnapshotHeapButton.setEnabled(false);

        mSnapshotHeapButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent evt) {
                snapshotHeap();
            }
        });
    }

    private void snapshotHeap() {
        Client c = getCurrentClient();
        assert c != null : "Snapshot Heap could not have been enabled w/o a selected client.";

        // send an async request
        c.requestNativeHeapInformation();
    }

    private void createLoadHeapDataButton(Composite parent) {
        mLoadHeapDataButton = new Button(parent, SWT.BORDER | SWT.PUSH);
        mLoadHeapDataButton.setText(LOAD_HEAP_DATA_BUTTON_TEXT);
        mLoadHeapDataButton.setLayoutData(new GridData());

        // disable by default, enabled only when a client is selected
        mLoadHeapDataButton.setEnabled(false);

        mLoadHeapDataButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent evt) {
                loadHeapDataFromFile();
            }
        });
    }

    private void loadHeapDataFromFile() {
        // pop up a file dialog and get the file to load
        final String path = getHeapDumpToImport();
        if (path == null) {
            return;
        }

        Reader reader = null;
        try {
            reader = new FileReader(path);
        } catch (FileNotFoundException e) {
            // cannot occur since user input was via a FileDialog
        }

        Shell shell = Display.getDefault().getActiveShell();
        ProgressMonitorDialog d = new ProgressMonitorDialog(shell);

        NativeHeapDataImporter importer = new NativeHeapDataImporter(reader);
        try {
            d.run(true, true, importer);
        } catch (InvocationTargetException e) {
            // exception while parsing, display error to user and then return
            MessageDialog.openError(shell,
                    "Error Importing Heap Data",
                    e.getCause().getMessage());
            return;
        } catch (InterruptedException e) {
            // operation cancelled by user, simply return
            return;
        }

        NativeHeapSnapshot snapshot = importer.getImportedSnapshot();

        addToImportedSnapshots(snapshot);   // save imported snapshot for future use
        addNativeHeapSnapshot(snapshot); // add to currently displayed snapshots as well

        updateDisplay();
    }

    private void addToImportedSnapshots(NativeHeapSnapshot snapshot) {
        Client c = getCurrentClient();

        if (c == null) {
            return;
        }

        Integer pid = c.getClientData().getPid();
        List<NativeHeapSnapshot> importedSnapshots = mImportedSnapshotsPerPid.get(pid);
        if (importedSnapshots == null) {
            importedSnapshots = new ArrayList<NativeHeapSnapshot>();
        }

        importedSnapshots.add(snapshot);
        mImportedSnapshotsPerPid.put(pid, importedSnapshots);
    }

    private String getHeapDumpToImport() {
        FileDialog fileDialog = new FileDialog(Display.getDefault().getActiveShell(),
                SWT.OPEN);

        fileDialog.setText("Import Heap Dump");
        fileDialog.setFilterExtensions(new String[] {"*.txt"});
        fileDialog.setFilterPath(mPrefStore.getString(PREFS_LAST_IMPORTED_HEAPPATH));

        String selectedFile = fileDialog.open();
        if (selectedFile != null) {
            // save the path to restore in future dialog open
            mPrefStore.setValue(PREFS_LAST_IMPORTED_HEAPPATH, new File(selectedFile).getParent());
        }
        return selectedFile;
    }

    private void createDisplaySection(Composite parent) {
        Composite c = new Composite(parent, SWT.NONE);
        c.setLayout(new GridLayout(2, false));
        c.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        // Create: Display: __________________
        createLabel(c, "Display:");
        mSnapshotIndexCombo = new Combo(c, SWT.READ_ONLY);
        mSnapshotIndexCombo.setItems(new String[] {"No heap snapshots available."});
        mSnapshotIndexCombo.setEnabled(false);
        mSnapshotIndexCombo.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                displaySelectedSnapshot();
            }
        });

        // Create: Memory Allocated (bytes): _________________
        createLabel(c, "Memory Allocated:");
        mMemoryAllocatedText = new Label(c, SWT.NONE);
        GridData gd = new GridData();
        gd.widthHint = 100;
        mMemoryAllocatedText.setLayoutData(gd);

        // Create: Search Path: __________________
        createLabel(c, SYMBOL_SEARCH_PATH_LABEL_TEXT);
        mSymbolSearchPathText = new Text(c, SWT.BORDER);
        mSymbolSearchPathText.setMessage(SYMBOL_SEARCH_PATH_TEXT_MESSAGE);
        mSymbolSearchPathText.setToolTipText(SYMBOL_SEARCH_PATH_TOOLTIP_TEXT);
        mSymbolSearchPathText.addModifyListener(new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent arg0) {
                String path = mSymbolSearchPathText.getText();
                updateSearchPath(path);
                mPrefStore.setValue(PREFS_SYMBOL_SEARCH_PATH, path);
            }
        });
        mSymbolSearchPathText.setText(mPrefStore.getString(PREFS_SYMBOL_SEARCH_PATH));
        mSymbolSearchPathText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
    }

    private void updateSearchPath(String path) {
        Addr2Line.setSearchPath(path);
    }

    private void createLabel(Composite parent, String text) {
        Label l = new Label(parent, SWT.NONE);
        l.setText(text);
        GridData gd = new GridData();
        gd.horizontalAlignment = SWT.RIGHT;
        l.setLayoutData(gd);
    }

    /**
     * Create the details section displaying the details table and the stack trace
     * corresponding to the selection.
     *
     * The details is laid out like so:
     *   Details Toolbar
     *   Details Table
     *   ------------sash---
     *   Stack Trace Label
     *   Stack Trace Text
     * There is a sash in between the two sections, and we need to save/restore the sash
     * preferences. Using FormLayout seems like the easiest solution here, but the layout
     * code looks ugly as a result.
     */
    private void createDetailsSection(Composite parent) {
        final Composite c = new Composite(parent, SWT.NONE);
        c.setLayout(new FormLayout());
        c.setLayoutData(new GridData(GridData.FILL_BOTH));

        ToolBar detailsToolBar = new ToolBar(c, SWT.FLAT | SWT.BORDER);
        initializeDetailsToolBar(detailsToolBar);

        Tree detailsTree = new Tree(c, SWT.VIRTUAL | SWT.BORDER | SWT.MULTI);
        initializeDetailsTree(detailsTree);

        final Sash sash = new Sash(c, SWT.HORIZONTAL | SWT.BORDER);

        Label stackTraceLabel = new Label(c, SWT.NONE);
        stackTraceLabel.setText("Stack Trace:");

        Tree stackTraceTree = new Tree(c, SWT.BORDER | SWT.MULTI);
        initializeStackTraceTree(stackTraceTree);

        // layout the widgets created above
        FormData data = new FormData();
        data.top    = new FormAttachment(0, 0);
        data.left   = new FormAttachment(0, 0);
        data.right  = new FormAttachment(100, 0);
        detailsToolBar.setLayoutData(data);

        data = new FormData();
        data.top    = new FormAttachment(detailsToolBar, 0);
        data.bottom = new FormAttachment(sash, 0);
        data.left   = new FormAttachment(0, 0);
        data.right  = new FormAttachment(100, 0);
        detailsTree.setLayoutData(data);

        final FormData sashData = new FormData();
        sashData.top    = new FormAttachment(mPrefStore.getInt(PREFS_SASH_HEIGHT_PERCENT), 0);
        sashData.left   = new FormAttachment(0, 0);
        sashData.right  = new FormAttachment(100, 0);
        sash.setLayoutData(sashData);

        data = new FormData();
        data.top    = new FormAttachment(sash, 0);
        data.left   = new FormAttachment(0, 0);
        data.right  = new FormAttachment(100, 0);
        stackTraceLabel.setLayoutData(data);

        data = new FormData();
        data.top    = new FormAttachment(stackTraceLabel, 0);
        data.left   = new FormAttachment(0, 0);
        data.bottom = new FormAttachment(100, 0);
        data.right  = new FormAttachment(100, 0);
        stackTraceTree.setLayoutData(data);

        sash.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event e) {
                Rectangle sashRect = sash.getBounds();
                Rectangle panelRect = c.getClientArea();
                int sashPercent = sashRect.y * 100 / panelRect.height;
                mPrefStore.setValue(PREFS_SASH_HEIGHT_PERCENT, sashPercent);

                sashData.top = new FormAttachment(0, e.y);
                c.layout();
            }
        });
    }

    private void initializeDetailsToolBar(ToolBar toolbar) {
        mGroupByButton = new ToolItem(toolbar, SWT.CHECK);
        mGroupByButton.setImage(ImageLoader.getDdmUiLibLoader().loadImage(GROUPBY_IMAGE,
                toolbar.getDisplay()));
        mGroupByButton.setToolTipText(TOOLTIP_GROUPBY);
        mGroupByButton.setSelection(mPrefStore.getBoolean(PREFS_GROUP_BY_LIBRARY));
        mGroupByButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                updateDisplayGrouping();
            }
        });

        mDiffsOnlyButton = new ToolItem(toolbar, SWT.CHECK);
        mDiffsOnlyButton.setImage(ImageLoader.getDdmUiLibLoader().loadImage(DIFFS_ONLY_IMAGE,
                toolbar.getDisplay()));
        mDiffsOnlyButton.setToolTipText(TOOLTIP_DIFFS_ONLY);
        mDiffsOnlyButton.setSelection(mPrefStore.getBoolean(PREFS_SHOW_DIFFS_ONLY));
        mDiffsOnlyButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                // simply refresh the display, as the display logic takes care of
                // the current state of the diffs only checkbox.
                int idx = mSnapshotIndexCombo.getSelectionIndex();
                displaySnapshot(idx);
            }
        });

        mShowZygoteAllocationsButton = new ToolItem(toolbar, SWT.CHECK);
        mShowZygoteAllocationsButton.setImage(ImageLoader.getDdmUiLibLoader().loadImage(
                ZYGOTE_IMAGE, toolbar.getDisplay()));
        mShowZygoteAllocationsButton.setToolTipText(TOOLTIP_ZYGOTE_ALLOCATIONS);
        mShowZygoteAllocationsButton.setSelection(
                mPrefStore.getBoolean(PREFS_SHOW_ZYGOTE_ALLOCATIONS));
        mShowZygoteAllocationsButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                updateDisplayForZygotes();
            }
        });

        mExportHeapDataButton = new ToolItem(toolbar, SWT.PUSH);
        mExportHeapDataButton.setImage(ImageLoader.getDdmUiLibLoader().loadImage(
                EXPORT_DATA_IMAGE, toolbar.getDisplay()));
        mExportHeapDataButton.setToolTipText(TOOLTIP_EXPORT_DATA);
        mExportHeapDataButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                exportSnapshot();
            }
        });
    }

    /** Export currently displayed snapshot to a file */
    private void exportSnapshot() {
        int idx = mSnapshotIndexCombo.getSelectionIndex();
        String snapshotName = mSnapshotIndexCombo.getItem(idx);

        FileDialog fileDialog = new FileDialog(Display.getDefault().getActiveShell(),
                SWT.SAVE);

        fileDialog.setText("Save " + snapshotName);
        fileDialog.setFileName("allocations.txt");

        final String fileName = fileDialog.open();
        if (fileName == null) {
            return;
        }

        final NativeHeapSnapshot snapshot = mNativeHeapSnapshots.get(idx);
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                PrintWriter out;
                try {
                    out = new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
                } catch (IOException e) {
                    displayErrorMessage(e.getMessage());
                    return;
                }

                for (NativeAllocationInfo alloc : snapshot.getAllocations()) {
                    out.println(alloc.toString());
                }
                out.close();
            }

            private void displayErrorMessage(final String message) {
                Display.getDefault().syncExec(new Runnable() {
                    @Override
                    public void run() {
                        MessageDialog.openError(Display.getDefault().getActiveShell(),
                                "Failed to export heap data", message);
                    }
                });
            }
        });
        t.setName("Saving Heap Data to File...");
        t.start();
    }

    private void initializeDetailsTree(Tree tree) {
        tree.setHeaderVisible(true);
        tree.setLinesVisible(true);

        List<String> properties = Arrays.asList("Library",
                "Total",
                "Percentage",
                "Count",
                "Size",
                "Method");

        List<String> sampleValues = Arrays.asList("/path/in/device/to/system/library.so",
                "123456789",
                " 100%",
                "123456789",
                "123456789",
                "PossiblyLongDemangledMethodName");

        // right align numeric values
        List<Integer> swtFlags = Arrays.asList(SWT.LEFT,
                SWT.RIGHT,
                SWT.RIGHT,
                SWT.RIGHT,
                SWT.RIGHT,
                SWT.LEFT);

        for (int i = 0; i < properties.size(); i++) {
            String p = properties.get(i);
            String v = sampleValues.get(i);
            int flags = swtFlags.get(i);
            TableHelper.createTreeColumn(tree, p, flags, v, getPref("details", p), mPrefStore);
        }

        mDetailsTreeViewer = new TreeViewer(tree);

        mDetailsTreeViewer.setUseHashlookup(true);

        boolean displayZygotes = mPrefStore.getBoolean(PREFS_SHOW_ZYGOTE_ALLOCATIONS);
        mContentProviderByAllocations = new NativeHeapProviderByAllocations(mDetailsTreeViewer,
                displayZygotes);
        mContentProviderByLibrary = new NativeHeapProviderByLibrary(mDetailsTreeViewer,
                displayZygotes);
        if (mPrefStore.getBoolean(PREFS_GROUP_BY_LIBRARY)) {
            mDetailsTreeViewer.setContentProvider(mContentProviderByLibrary);
        } else {
            mDetailsTreeViewer.setContentProvider(mContentProviderByAllocations);
        }

        mDetailsTreeLabelProvider = new NativeHeapLabelProvider();
        mDetailsTreeViewer.setLabelProvider(mDetailsTreeLabelProvider);

        mDetailsTreeViewer.setInput(null);

        tree.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                displayStackTraceForSelection();
            }
        });
    }

    private void initializeStackTraceTree(Tree tree) {
        tree.setHeaderVisible(true);
        tree.setLinesVisible(true);

        List<String> properties = Arrays.asList("Address",
                "Library",
                "Method",
                "File",
                "Line");

        List<String> sampleValues = Arrays.asList("0x1234_5678",
                "/path/in/device/to/system/library.so",
                "PossiblyLongDemangledMethodName",
                "/android/out/prefix/in/home/directory/to/path/in/device/to/system/library.so",
                "2000");

        for (int i = 0; i < properties.size(); i++) {
            String p = properties.get(i);
            String v = sampleValues.get(i);
            TableHelper.createTreeColumn(tree, p, SWT.LEFT, v, getPref("stack", p), mPrefStore);
        }

        mStackTraceTreeViewer = new TreeViewer(tree);

        mStackTraceTreeViewer.setContentProvider(new NativeStackContentProvider());
        mStackTraceTreeViewer.setLabelProvider(new NativeStackLabelProvider());

        mStackTraceTreeViewer.setInput(null);
    }

    private void displayStackTraceForSelection() {
        TreeItem []items = mDetailsTreeViewer.getTree().getSelection();
        if (items.length == 0) {
            mStackTraceTreeViewer.setInput(null);
            return;
        }

        Object data = items[0].getData();
        if (!(data instanceof NativeAllocationInfo)) {
            mStackTraceTreeViewer.setInput(null);
            return;
        }

        NativeAllocationInfo info = (NativeAllocationInfo) data;
        if (info.isStackCallResolved()) {
            mStackTraceTreeViewer.setInput(info.getResolvedStackCall());
        } else {
            mStackTraceTreeViewer.setInput(info.getStackCallAddresses());
        }
    }

    private String getPref(String prefix, String s) {
        return "nativeheap.tree." + prefix + "." + s;
    }

    @Override
    public void setFocus() {
    }

    private ITableFocusListener mTableFocusListener;

    @Override
    public void setTableFocusListener(ITableFocusListener listener) {
        mTableFocusListener = listener;

        final Tree heapSitesTree = mDetailsTreeViewer.getTree();
        final IFocusedTableActivator heapSitesActivator = new IFocusedTableActivator() {
            @Override
            public void copy(Clipboard clipboard) {
                TreeItem[] items = heapSitesTree.getSelection();
                copyToClipboard(items, clipboard);
            }

            @Override
            public void selectAll() {
                heapSitesTree.selectAll();
            }
        };

        heapSitesTree.addFocusListener(new FocusListener() {
            @Override
            public void focusLost(FocusEvent arg0) {
                mTableFocusListener.focusLost(heapSitesActivator);
            }

            @Override
            public void focusGained(FocusEvent arg0) {
                mTableFocusListener.focusGained(heapSitesActivator);
            }
        });

        final Tree stackTraceTree = mStackTraceTreeViewer.getTree();
        final IFocusedTableActivator stackTraceActivator = new IFocusedTableActivator() {
            @Override
            public void copy(Clipboard clipboard) {
                TreeItem[] items = stackTraceTree.getSelection();
                copyToClipboard(items, clipboard);
            }

            @Override
            public void selectAll() {
                stackTraceTree.selectAll();
            }
        };

        stackTraceTree.addFocusListener(new FocusListener() {
            @Override
            public void focusLost(FocusEvent arg0) {
                mTableFocusListener.focusLost(stackTraceActivator);
            }

            @Override
            public void focusGained(FocusEvent arg0) {
                mTableFocusListener.focusGained(stackTraceActivator);
            }
        });
    }

    private void copyToClipboard(TreeItem[] items, Clipboard clipboard) {
        StringBuilder sb = new StringBuilder();

        for (TreeItem item : items) {
            Object data = item.getData();
            if (data != null) {
                sb.append(data.toString());
                sb.append('\n');
            }
        }

        String content = sb.toString();
        if (content.length() > 0) {
            clipboard.setContents(
                    new Object[] {sb.toString()},
                    new Transfer[] {TextTransfer.getInstance()}
                    );
        }
    }

    private class SymbolResolverTask implements Runnable {
        private List<NativeAllocationInfo> mCallSites;
        private List<NativeLibraryMapInfo> mMappedLibraries;
        private Map<Long, NativeStackCallInfo> mResolvedSymbolCache;

        public SymbolResolverTask(List<NativeAllocationInfo> callSites,
                List<NativeLibraryMapInfo> mappedLibraries) {
            mCallSites = callSites;
            mMappedLibraries = mappedLibraries;

            mResolvedSymbolCache = new HashMap<Long, NativeStackCallInfo>();
        }

        @Override
        public void run() {
            for (NativeAllocationInfo callSite : mCallSites) {
                if (callSite.isStackCallResolved()) {
                    continue;
                }

                List<Long> addresses = callSite.getStackCallAddresses();
                List<NativeStackCallInfo> resolvedStackInfo =
                        new ArrayList<NativeStackCallInfo>(addresses.size());

                for (Long address : addresses) {
                    NativeStackCallInfo info = mResolvedSymbolCache.get(address);

                    if (info != null) {
                        resolvedStackInfo.add(info);
                    } else {
                        info = resolveAddress(address);
                        resolvedStackInfo.add(info);
                        mResolvedSymbolCache.put(address, info);
                    }
                }

                callSite.setResolvedStackCall(resolvedStackInfo);
            }

            Display.getDefault().asyncExec(new Runnable() {
                @Override
                public void run() {
                    mDetailsTreeViewer.refresh();
                    mStackTraceTreeViewer.refresh();
                }
            });
        }

        private NativeStackCallInfo resolveAddress(long addr) {
            NativeLibraryMapInfo library = getLibraryFor(addr);

            if (library != null) {
                Client c = getCurrentClient();
                Addr2Line process = Addr2Line.getProcess(library, c.getClientData().getAbi());
                if (process != null) {
                    NativeStackCallInfo info = process.getAddress(addr);
                    if (info != null) {
                        return info;
                    }
                }
            }

            return new NativeStackCallInfo(addr,
                    library != null ? library.getLibraryName() : null,
                    Long.toHexString(addr),
                    "");
        }

        private NativeLibraryMapInfo getLibraryFor(long addr) {
            for (NativeLibraryMapInfo info : mMappedLibraries) {
                if (info.isWithinLibrary(addr)) {
                    return info;
                }
            }

            Log.d("ddm-nativeheap", "Failed finding Library for " + Long.toHexString(addr));
            return null;
        }
    }
}

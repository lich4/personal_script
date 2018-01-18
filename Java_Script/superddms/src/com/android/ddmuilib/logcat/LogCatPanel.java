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

import com.android.ddmlib.DdmConstants;
import com.android.ddmlib.IDevice;
import com.android.ddmlib.Log.LogLevel;
import com.android.ddmlib.logcat.LogCatFilter;
import com.android.ddmlib.logcat.LogCatMessage;
import com.android.ddmuilib.AbstractBufferFindTarget;
import com.android.ddmuilib.FindDialog;
import com.android.ddmuilib.ITableFocusListener;
import com.android.ddmuilib.ITableFocusListener.IFocusedTableActivator;
import com.android.ddmuilib.ImageLoader;
import com.android.ddmuilib.SelectionDependentPanel;
import com.android.ddmuilib.TableHelper;

import org.eclipse.jface.action.Action;
import org.eclipse.jface.action.MenuManager;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.jface.preference.PreferenceConverter;
import org.eclipse.jface.util.IPropertyChangeListener;
import org.eclipse.jface.util.PropertyChangeEvent;
import org.eclipse.jface.viewers.TableViewer;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.dnd.Clipboard;
import org.eclipse.swt.dnd.TextTransfer;
import org.eclipse.swt.dnd.Transfer;
import org.eclipse.swt.events.ControlAdapter;
import org.eclipse.swt.events.ControlEvent;
import org.eclipse.swt.events.DisposeEvent;
import org.eclipse.swt.events.DisposeListener;
import org.eclipse.swt.events.FocusEvent;
import org.eclipse.swt.events.FocusListener;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.FontData;
import org.eclipse.swt.graphics.GC;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.graphics.RGB;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.ScrollBar;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.widgets.ToolBar;
import org.eclipse.swt.widgets.ToolItem;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * LogCatPanel displays a table listing the logcat messages.
 */
public final class LogCatPanel extends SelectionDependentPanel
                        implements ILogCatBufferChangeListener {
    /** Preference key to use for storing list of logcat filters. */
    public static final String LOGCAT_FILTERS_LIST = "logcat.view.filters.list";

    /** Preference key to use for storing font settings. */
    public static final String LOGCAT_VIEW_FONT_PREFKEY = "logcat.view.font";

    /** Preference key to use for deciding whether to automatically en/disable scroll lock. */
    public static final String AUTO_SCROLL_LOCK_PREFKEY = "logcat.view.auto-scroll-lock";

    // Preference keys for message colors based on severity level
    private static final String MSG_COLOR_PREFKEY_PREFIX = "logcat.msg.color.";
    public static final String VERBOSE_COLOR_PREFKEY = MSG_COLOR_PREFKEY_PREFIX + "verbose"; //$NON-NLS-1$
    public static final String DEBUG_COLOR_PREFKEY = MSG_COLOR_PREFKEY_PREFIX + "debug"; //$NON-NLS-1$
    public static final String INFO_COLOR_PREFKEY = MSG_COLOR_PREFKEY_PREFIX + "info"; //$NON-NLS-1$
    public static final String WARN_COLOR_PREFKEY = MSG_COLOR_PREFKEY_PREFIX + "warn"; //$NON-NLS-1$
    public static final String ERROR_COLOR_PREFKEY = MSG_COLOR_PREFKEY_PREFIX + "error"; //$NON-NLS-1$
    public static final String ASSERT_COLOR_PREFKEY = MSG_COLOR_PREFKEY_PREFIX + "assert"; //$NON-NLS-1$

    // Use a monospace font family
    private static final String FONT_FAMILY =
            DdmConstants.CURRENT_PLATFORM == DdmConstants.PLATFORM_DARWIN ? "Monaco":"Courier New";

    // Use the default system font size
    private static final FontData DEFAULT_LOGCAT_FONTDATA;
    static {
        int h = Display.getDefault().getSystemFont().getFontData()[0].getHeight();
        DEFAULT_LOGCAT_FONTDATA = new FontData(FONT_FAMILY, h, SWT.NORMAL);
    }

    private static final String LOGCAT_VIEW_COLSIZE_PREFKEY_PREFIX = "logcat.view.colsize.";
    private static final String DISPLAY_FILTERS_COLUMN_PREFKEY = "logcat.view.display.filters";

    /** Default message to show in the message search field. */
    private static final String DEFAULT_SEARCH_MESSAGE =
            "Search for messages. Accepts Java regexes. "
            + "Prefix with pid:, app:, tag: or text: to limit scope.";

    /** Tooltip to show in the message search field. */
    private static final String DEFAULT_SEARCH_TOOLTIP =
            "Example search patterns:\n"
          + "    sqlite (search for sqlite in text field)\n"
          + "    app:browser (search for messages generated by the browser application)";

    private static final String IMAGE_ADD_FILTER = "add.png"; //$NON-NLS-1$
    private static final String IMAGE_DELETE_FILTER = "delete.png"; //$NON-NLS-1$
    private static final String IMAGE_EDIT_FILTER = "edit.png"; //$NON-NLS-1$
    private static final String IMAGE_SAVE_LOG_TO_FILE = "save.png"; //$NON-NLS-1$
    private static final String IMAGE_CLEAR_LOG = "clear.png"; //$NON-NLS-1$
    private static final String IMAGE_DISPLAY_FILTERS = "displayfilters.png"; //$NON-NLS-1$
    private static final String IMAGE_SCROLL_LOCK = "scroll_lock.png"; //$NON-NLS-1$

    private static final int[] WEIGHTS_SHOW_FILTERS = new int[] {15, 85};
    private static final int[] WEIGHTS_LOGCAT_ONLY = new int[] {0, 100};

    /** Index of the default filter in the saved filters column. */
    private static final int DEFAULT_FILTER_INDEX = 0;

    /* Text colors for the filter box */
    private static final Color VALID_FILTER_REGEX_COLOR =
            Display.getDefault().getSystemColor(SWT.COLOR_BLACK);
    private static final Color INVALID_FILTER_REGEX_COLOR =
            Display.getDefault().getSystemColor(SWT.COLOR_RED);

    private LogCatReceiver mReceiver;
    private IPreferenceStore mPrefStore;

    private List<LogCatFilter> mLogCatFilters;
    private Map<LogCatFilter, LogCatFilterData> mLogCatFilterData;
    private int mCurrentSelectedFilterIndex;

    private ToolItem mNewFilterToolItem;
    private ToolItem mDeleteFilterToolItem;
    private ToolItem mEditFilterToolItem;
    private TableViewer mFiltersTableViewer;

    private Combo mLiveFilterLevelCombo;
    private Text mLiveFilterText;

    private List<LogCatFilter> mCurrentFilters = Collections.emptyList();

    private Table mTable;

    private boolean mShouldScrollToLatestLog = true;
    private ToolItem mScrollLockCheckBox;
    private boolean mAutoScrollLock;

    // Lock under which the vertical scroll bar listener should be added
    private final Object mScrollBarSelectionListenerLock = new Object();
    private SelectionListener mScrollBarSelectionListener;
    private boolean mScrollBarListenerSet = false;

    private String mLogFileExportFolder;

    private Font mFont;
    private int mWrapWidthInChars;

    private Color mVerboseColor;
    private Color mDebugColor;
    private Color mInfoColor;
    private Color mWarnColor;
    private Color mErrorColor;
    private Color mAssertColor;

    private SashForm mSash;

    // messages added since last refresh, synchronized on mLogBuffer
    private List<LogCatMessage> mLogBuffer;

    // # of messages deleted since last refresh, synchronized on mLogBuffer
    private int mDeletedLogCount;

    /**
     * Construct a logcat panel.
     * @param prefStore preference store where UI preferences will be saved
     */
    public LogCatPanel(IPreferenceStore prefStore) {
        mPrefStore = prefStore;
        mLogBuffer = new ArrayList<LogCatMessage>(LogCatMessageList.MAX_MESSAGES_DEFAULT);

        initializeFilters();

        setupDefaultPreferences();
        initializePreferenceUpdateListeners();

        mFont = getFontFromPrefStore();
        loadMessageColorPreferences();
        mAutoScrollLock = mPrefStore.getBoolean(AUTO_SCROLL_LOCK_PREFKEY);
    }

    private void loadMessageColorPreferences() {
        if (mVerboseColor != null) {
            disposeMessageColors();
        }

        mVerboseColor = getColorFromPrefStore(VERBOSE_COLOR_PREFKEY);
        mDebugColor = getColorFromPrefStore(DEBUG_COLOR_PREFKEY);
        mInfoColor = getColorFromPrefStore(INFO_COLOR_PREFKEY);
        mWarnColor = getColorFromPrefStore(WARN_COLOR_PREFKEY);
        mErrorColor = getColorFromPrefStore(ERROR_COLOR_PREFKEY);
        mAssertColor = getColorFromPrefStore(ASSERT_COLOR_PREFKEY);
    }

    private void initializeFilters() {
        mLogCatFilters = new ArrayList<LogCatFilter>();
        mLogCatFilterData = new ConcurrentHashMap<LogCatFilter, LogCatFilterData>();

        /* add default filter matching all messages */
        String tag = "";
        String text = "";
        String pid = "";
        String app = "";
        LogCatFilter defaultFilter = new LogCatFilter("All messages (no filters)",
                tag, text, pid, app, LogLevel.VERBOSE);

        mLogCatFilters.add(defaultFilter);
        mLogCatFilterData.put(defaultFilter, new LogCatFilterData(defaultFilter));

        /* restore saved filters from prefStore */
        List<LogCatFilter> savedFilters = getSavedFilters();
        for (LogCatFilter f: savedFilters) {
            mLogCatFilters.add(f);
            mLogCatFilterData.put(f, new LogCatFilterData(f));
        }
    }

    private void setupDefaultPreferences() {
        PreferenceConverter.setDefault(mPrefStore, LogCatPanel.LOGCAT_VIEW_FONT_PREFKEY,
                DEFAULT_LOGCAT_FONTDATA);
        mPrefStore.setDefault(LogCatMessageList.MAX_MESSAGES_PREFKEY,
                LogCatMessageList.MAX_MESSAGES_DEFAULT);
        mPrefStore.setDefault(DISPLAY_FILTERS_COLUMN_PREFKEY, true);
        mPrefStore.setDefault(AUTO_SCROLL_LOCK_PREFKEY, true);

        /* Default Colors for different log levels. */
        PreferenceConverter.setDefault(mPrefStore, LogCatPanel.VERBOSE_COLOR_PREFKEY,
                new RGB(0, 0, 0));
        PreferenceConverter.setDefault(mPrefStore, LogCatPanel.DEBUG_COLOR_PREFKEY,
                new RGB(0, 0, 127));
        PreferenceConverter.setDefault(mPrefStore, LogCatPanel.INFO_COLOR_PREFKEY,
                new RGB(0, 127, 0));
        PreferenceConverter.setDefault(mPrefStore, LogCatPanel.WARN_COLOR_PREFKEY,
                new RGB(255, 127, 0));
        PreferenceConverter.setDefault(mPrefStore, LogCatPanel.ERROR_COLOR_PREFKEY,
                new RGB(255, 0, 0));
        PreferenceConverter.setDefault(mPrefStore, LogCatPanel.ASSERT_COLOR_PREFKEY,
                new RGB(255, 0, 0));
    }

    private void initializePreferenceUpdateListeners() {
        mPrefStore.addPropertyChangeListener(new IPropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent event) {
                String changedProperty = event.getProperty();
                if (changedProperty.equals(LogCatPanel.LOGCAT_VIEW_FONT_PREFKEY)) {
                    if (mFont != null) {
                        mFont.dispose();
                    }
                    mFont = getFontFromPrefStore();
                    recomputeWrapWidth();
                    Display.getDefault().syncExec(new Runnable() {
                        @Override
                        public void run() {
                            for (TableItem it: mTable.getItems()) {
                                it.setFont(mFont);
                            }
                        }
                    });
                } else if (changedProperty.startsWith(MSG_COLOR_PREFKEY_PREFIX)) {
                    loadMessageColorPreferences();
                    Display.getDefault().syncExec(new Runnable() {
                       @Override
                       public void run() {
                           Color c = mVerboseColor;
                           for (TableItem it: mTable.getItems()) {
                               Object data = it.getData();
                               if (data instanceof LogCatMessage) {
                                   c = getForegroundColor((LogCatMessage) data);
                               }
                               it.setForeground(c);
                           }
                       }
                    });
                } else if (changedProperty.equals(LogCatMessageList.MAX_MESSAGES_PREFKEY)) {
                    mReceiver.resizeFifo(mPrefStore.getInt(
                            LogCatMessageList.MAX_MESSAGES_PREFKEY));
                    reloadLogBuffer();
                } else if (changedProperty.equals(AUTO_SCROLL_LOCK_PREFKEY)) {
                    mAutoScrollLock = mPrefStore.getBoolean(AUTO_SCROLL_LOCK_PREFKEY);
                }
            }
        });
    }

    private void saveFilterPreferences() {
        LogCatFilterSettingsSerializer serializer = new LogCatFilterSettingsSerializer();

        /* save all filter settings except the first one which is the default */
        String e = serializer.encodeToPreferenceString(
                mLogCatFilters.subList(1, mLogCatFilters.size()), mLogCatFilterData);
        mPrefStore.setValue(LOGCAT_FILTERS_LIST, e);
    }

    private List<LogCatFilter> getSavedFilters() {
        LogCatFilterSettingsSerializer serializer = new LogCatFilterSettingsSerializer();
        String e = mPrefStore.getString(LOGCAT_FILTERS_LIST);
        return serializer.decodeFromPreferenceString(e);
    }

    @Override
    public void deviceSelected() {
        IDevice device = getCurrentDevice();
        if (device == null) {
            // If the device is not working properly, getCurrentDevice() could return null.
            // In such a case, we don't launch logcat, nor switch the display.
            return;
        }

        if (mReceiver != null) {
            // Don't need to listen to new logcat messages from previous device anymore.
            mReceiver.removeMessageReceivedEventListener(this);

            // When switching between devices, existing filter match count should be reset.
            for (LogCatFilter f : mLogCatFilters) {
                LogCatFilterData fd = mLogCatFilterData.get(f);
                fd.resetUnreadCount();
            }
        }

        mReceiver = LogCatReceiverFactory.INSTANCE.newReceiver(device, mPrefStore);
        mReceiver.addMessageReceivedEventListener(this);
        reloadLogBuffer();

        // Always scroll to last line whenever the selected device changes.
        // Run this in a separate async thread to give the table some time to update after the
        // setInput above.
        Display.getDefault().asyncExec(new Runnable() {
            @Override
            public void run() {
                scrollToLatestLog();
            }
        });
    }

    @Override
    public void clientSelected() {
    }

    @Override
    protected void postCreation() {
    }

    @Override
    protected Control createControl(Composite parent) {
        GridLayout layout = new GridLayout(1, false);
        parent.setLayout(layout);

        createViews(parent);
        setupDefaults();

        return null;
    }

    private void createViews(Composite parent) {
        mSash = createSash(parent);

        createListOfFilters(mSash);
        createLogTableView(mSash);

        boolean showFilters = mPrefStore.getBoolean(DISPLAY_FILTERS_COLUMN_PREFKEY);
        updateFiltersColumn(showFilters);
    }

    private SashForm createSash(Composite parent) {
        SashForm sash = new SashForm(parent, SWT.HORIZONTAL);
        sash.setLayoutData(new GridData(GridData.FILL_BOTH));
        return sash;
    }

    private void createListOfFilters(SashForm sash) {
        Composite c = new Composite(sash, SWT.BORDER);
        GridLayout layout = new GridLayout(2, false);
        c.setLayout(layout);
        c.setLayoutData(new GridData(GridData.FILL_BOTH));

        createFiltersToolbar(c);
        createFiltersTable(c);
    }

    private void createFiltersToolbar(Composite parent) {
        Label l = new Label(parent, SWT.NONE);
        l.setText("Saved Filters");
        GridData gd = new GridData();
        gd.horizontalAlignment = SWT.LEFT;
        l.setLayoutData(gd);

        ToolBar t = new ToolBar(parent, SWT.FLAT);
        gd = new GridData();
        gd.horizontalAlignment = SWT.RIGHT;
        t.setLayoutData(gd);

        /* new filter */
        mNewFilterToolItem = new ToolItem(t, SWT.PUSH);
        mNewFilterToolItem.setImage(
                ImageLoader.getDdmUiLibLoader().loadImage(IMAGE_ADD_FILTER, t.getDisplay()));
        mNewFilterToolItem.setToolTipText("Add a new logcat filter");
        mNewFilterToolItem.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                addNewFilter();
            }
        });

        /* delete filter */
        mDeleteFilterToolItem = new ToolItem(t, SWT.PUSH);
        mDeleteFilterToolItem.setImage(
                ImageLoader.getDdmUiLibLoader().loadImage(IMAGE_DELETE_FILTER, t.getDisplay()));
        mDeleteFilterToolItem.setToolTipText("Delete selected logcat filter");
        mDeleteFilterToolItem.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                deleteSelectedFilter();
            }
        });

        /* edit filter */
        mEditFilterToolItem = new ToolItem(t, SWT.PUSH);
        mEditFilterToolItem.setImage(
                ImageLoader.getDdmUiLibLoader().loadImage(IMAGE_EDIT_FILTER, t.getDisplay()));
        mEditFilterToolItem.setToolTipText("Edit selected logcat filter");
        mEditFilterToolItem.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                editSelectedFilter();
            }
        });
    }

    private void addNewFilter(String defaultTag, String defaultText, String defaultPid,
            String defaultAppName, LogLevel defaultLevel) {
        LogCatFilterSettingsDialog d = new LogCatFilterSettingsDialog(
                Display.getCurrent().getActiveShell());
        d.setDefaults("", defaultTag, defaultText, defaultPid, defaultAppName, defaultLevel);
        if (d.open() != Window.OK) {
            return;
        }

        LogCatFilter f = new LogCatFilter(d.getFilterName().trim(),
                d.getTag().trim(),
                d.getText().trim(),
                d.getPid().trim(),
                d.getAppName().trim(),
                LogLevel.getByString(d.getLogLevel()));

        mLogCatFilters.add(f);
        mLogCatFilterData.put(f, new LogCatFilterData(f));
        mFiltersTableViewer.refresh();

        /* select the newly added entry */
        int idx = mLogCatFilters.size() - 1;
        mFiltersTableViewer.getTable().setSelection(idx);

        filterSelectionChanged();
        saveFilterPreferences();
    }

    private void addNewFilter() {
        addNewFilter("", "", "", "", LogLevel.VERBOSE);
    }

    private void deleteSelectedFilter() {
        int selectedIndex = mFiltersTableViewer.getTable().getSelectionIndex();
        if (selectedIndex <= 0) {
            /* return if no selected filter, or the default filter was selected (0th). */
            return;
        }

        LogCatFilter f = mLogCatFilters.get(selectedIndex);
        mLogCatFilters.remove(selectedIndex);
        mLogCatFilterData.remove(f);

        mFiltersTableViewer.refresh();
        mFiltersTableViewer.getTable().setSelection(selectedIndex - 1);

        filterSelectionChanged();
        saveFilterPreferences();
    }

    private void editSelectedFilter() {
        int selectedIndex = mFiltersTableViewer.getTable().getSelectionIndex();
        if (selectedIndex < 0) {
            return;
        }

        LogCatFilter curFilter = mLogCatFilters.get(selectedIndex);

        LogCatFilterSettingsDialog dialog = new LogCatFilterSettingsDialog(
                Display.getCurrent().getActiveShell());
        dialog.setDefaults(curFilter.getName(), curFilter.getTag(), curFilter.getText(),
                curFilter.getPid(), curFilter.getAppName(), curFilter.getLogLevel());
        if (dialog.open() != Window.OK) {
            return;
        }

        LogCatFilter f = new LogCatFilter(dialog.getFilterName(),
                dialog.getTag(),
                dialog.getText(),
                dialog.getPid(),
                dialog.getAppName(),
                LogLevel.getByString(dialog.getLogLevel()));
        mLogCatFilters.set(selectedIndex, f);
        mFiltersTableViewer.refresh();

        mFiltersTableViewer.getTable().setSelection(selectedIndex);
        filterSelectionChanged();
        saveFilterPreferences();
    }

    /**
     * Select the transient filter for the specified application. If no such filter
     * exists, then create one and then select that. This method should be called from
     * the UI thread.
     * @param appName application name to filter by
     */
    public void selectTransientAppFilter(String appName) {
        assert mTable.getDisplay().getThread() == Thread.currentThread();

        LogCatFilter f = findTransientAppFilter(appName);
        if (f == null) {
            f = createTransientAppFilter(appName);
            mLogCatFilters.add(f);

            LogCatFilterData fd = new LogCatFilterData(f);
            fd.setTransient();
            mLogCatFilterData.put(f, fd);
        }

        selectFilterAt(mLogCatFilters.indexOf(f));
    }

    private LogCatFilter findTransientAppFilter(String appName) {
        for (LogCatFilter f : mLogCatFilters) {
            LogCatFilterData fd = mLogCatFilterData.get(f);
            if (fd != null && fd.isTransient() && f.getAppName().equals(appName)) {
                return f;
            }
        }
        return null;
    }

    private LogCatFilter createTransientAppFilter(String appName) {
        LogCatFilter f = new LogCatFilter(appName + " (Session Filter)",
                "",
                "",
                "",
                appName,
                LogLevel.VERBOSE);
        return f;
    }

    private void selectFilterAt(final int index) {
        mFiltersTableViewer.refresh();

        if (index != mFiltersTableViewer.getTable().getSelectionIndex()) {
            mFiltersTableViewer.getTable().setSelection(index);
            filterSelectionChanged();
        }
    }

    private void createFiltersTable(Composite parent) {
        final Table table = new Table(parent, SWT.FULL_SELECTION);

        GridData gd = new GridData(GridData.FILL_BOTH);
        gd.horizontalSpan = 2;
        table.setLayoutData(gd);

        mFiltersTableViewer = new TableViewer(table);
        mFiltersTableViewer.setContentProvider(new LogCatFilterContentProvider());
        mFiltersTableViewer.setLabelProvider(new LogCatFilterLabelProvider(mLogCatFilterData));
        mFiltersTableViewer.setInput(mLogCatFilters);

        mFiltersTableViewer.getTable().addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                filterSelectionChanged();
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent arg0) {
                editSelectedFilter();
            }
        });
    }

    private void createLogTableView(SashForm sash) {
        Composite c = new Composite(sash, SWT.NONE);
        c.setLayout(new GridLayout());
        c.setLayoutData(new GridData(GridData.FILL_BOTH));

        createLiveFilters(c);
        createLogcatViewTable(c);
    }

    /** Create the search bar at the top of the logcat messages table. */
    private void createLiveFilters(Composite parent) {
        Composite c = new Composite(parent, SWT.NONE);
        c.setLayout(new GridLayout(3, false));
        c.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        mLiveFilterText = new Text(c, SWT.BORDER | SWT.SEARCH);
        mLiveFilterText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        mLiveFilterText.setMessage(DEFAULT_SEARCH_MESSAGE);
        mLiveFilterText.setToolTipText(DEFAULT_SEARCH_TOOLTIP);
        mLiveFilterText.addModifyListener(new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent arg0) {
                updateFilterTextColor();
                updateAppliedFilters();
            }
        });

        mLiveFilterLevelCombo = new Combo(c, SWT.READ_ONLY | SWT.DROP_DOWN);
        mLiveFilterLevelCombo.setItems(
                LogCatFilterSettingsDialog.getLogLevels().toArray(new String[0]));
        mLiveFilterLevelCombo.select(0);
        mLiveFilterLevelCombo.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                updateAppliedFilters();
            }
        });

        ToolBar toolBar = new ToolBar(c, SWT.FLAT);

        ToolItem saveToLog = new ToolItem(toolBar, SWT.PUSH);
        saveToLog.setImage(ImageLoader.getDdmUiLibLoader().loadImage(IMAGE_SAVE_LOG_TO_FILE,
                toolBar.getDisplay()));
        saveToLog.setToolTipText("Export Selected Items To Text File..");
        saveToLog.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                saveLogToFile();
            }
        });

        ToolItem clearLog = new ToolItem(toolBar, SWT.PUSH);
        clearLog.setImage(
                ImageLoader.getDdmUiLibLoader().loadImage(IMAGE_CLEAR_LOG, toolBar.getDisplay()));
        clearLog.setToolTipText("Clear Log");
        clearLog.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent arg0) {
                if (mReceiver != null) {
                    mReceiver.clearMessages();
                    refreshLogCatTable();
                    resetUnreadCountForAllFilters();

                    // the filters view is not cleared unless the filters are re-applied.
                    updateAppliedFilters();
                }
            }
        });

        final ToolItem showFiltersColumn = new ToolItem(toolBar, SWT.CHECK);
        showFiltersColumn.setImage(
                ImageLoader.getDdmUiLibLoader().loadImage(IMAGE_DISPLAY_FILTERS,
                        toolBar.getDisplay()));
        showFiltersColumn.setSelection(mPrefStore.getBoolean(DISPLAY_FILTERS_COLUMN_PREFKEY));
        showFiltersColumn.setToolTipText("Display Saved Filters View");
        showFiltersColumn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                boolean showFilters = showFiltersColumn.getSelection();
                mPrefStore.setValue(DISPLAY_FILTERS_COLUMN_PREFKEY, showFilters);
                updateFiltersColumn(showFilters);
            }
        });

        mScrollLockCheckBox = new ToolItem(toolBar, SWT.CHECK);
        mScrollLockCheckBox.setImage(
                ImageLoader.getDdmUiLibLoader().loadImage(IMAGE_SCROLL_LOCK,
                        toolBar.getDisplay()));
        mScrollLockCheckBox.setSelection(true);
        mScrollLockCheckBox.setToolTipText("Scroll Lock");
        mScrollLockCheckBox.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                boolean scrollLock = mScrollLockCheckBox.getSelection();
                setScrollToLatestLog(scrollLock);
            }
        });
    }

    /** Sets the foreground color of filter text based on whether the regex is valid. */
    private void updateFilterTextColor() {
        String text = mLiveFilterText.getText();
        Color c;
        try {
            Pattern.compile(text.trim());
            c = VALID_FILTER_REGEX_COLOR;
        } catch (PatternSyntaxException e) {
            c = INVALID_FILTER_REGEX_COLOR;
        }
        mLiveFilterText.setForeground(c);
    }

    private void updateFiltersColumn(boolean showFilters) {
        if (showFilters) {
            mSash.setWeights(WEIGHTS_SHOW_FILTERS);
        } else {
            mSash.setWeights(WEIGHTS_LOGCAT_ONLY);
        }
    }

    /**
     * Save logcat messages selected in the table to a file.
     */
    private void saveLogToFile() {
        /* show dialog box and get target file name */
        final String fName = getLogFileTargetLocation();
        if (fName == null) {
            return;
        }

        /* obtain list of selected messages */
        final List<LogCatMessage> selectedMessages = getSelectedLogCatMessages();

        /* save messages to file in a different (non UI) thread */
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                BufferedWriter w = null;
                try {
                    w = new BufferedWriter(new FileWriter(fName));
                    for (LogCatMessage m : selectedMessages) {
                        w.append(m.toString());
                        w.newLine();
                    }
                } catch (final IOException e) {
                    Display.getDefault().asyncExec(new Runnable() {
                        @Override
                        public void run() {
                            MessageDialog.openError(Display.getCurrent().getActiveShell(),
                                    "Unable to export selection to file.",
                                    "Unexpected error while saving selected messages to file: "
                                            + e.getMessage());
                        }
                    });
                } finally {
                    if (w != null) {
                        try {
                            w.close();
                        } catch (IOException e) {
                            // ignore
                        }
                    }
                }
            }
        });
        t.setName("Saving selected items to logfile..");
        t.start();
    }

    /**
     * Display a {@link FileDialog} to the user and obtain the location for the log file.
     * @return path to target file, null if user canceled the dialog
     */
    private String getLogFileTargetLocation() {
        FileDialog fd = new FileDialog(Display.getCurrent().getActiveShell(), SWT.SAVE);

        fd.setText("Save Log..");
        fd.setFileName("log.txt");

        if (mLogFileExportFolder == null) {
            mLogFileExportFolder = System.getProperty("user.home");
        }
        fd.setFilterPath(mLogFileExportFolder);

        fd.setFilterNames(new String[] {
                "Text Files (*.txt)"
        });
        fd.setFilterExtensions(new String[] {
                "*.txt"
        });

        String fName = fd.open();
        if (fName != null) {
            mLogFileExportFolder = fd.getFilterPath();  /* save path to restore on future calls */
        }

        return fName;
    }

    private List<LogCatMessage> getSelectedLogCatMessages() {
        int[] indices = mTable.getSelectionIndices();
        Arrays.sort(indices); /* Table.getSelectionIndices() does not specify an order */

        List<LogCatMessage> selectedMessages = new ArrayList<LogCatMessage>(indices.length);
        for (int i : indices) {
            Object data = mTable.getItem(i).getData();
            if (data instanceof LogCatMessage) {
                selectedMessages.add((LogCatMessage) data);
            }
        }

        return selectedMessages;
    }

    private List<LogCatMessage> applyCurrentFilters(List<LogCatMessage> msgList) {
        List<LogCatMessage> filteredItems = new ArrayList<LogCatMessage>(msgList.size());

        for (LogCatMessage msg: msgList) {
            if (isMessageAccepted(msg, mCurrentFilters)) {
                filteredItems.add(msg);
            }
        }

        return filteredItems;
    }

    private boolean isMessageAccepted(LogCatMessage msg, List<LogCatFilter> filters) {
        for (LogCatFilter f : filters) {
            if (!f.matches(msg)) {
                // not accepted by this filter
                return false;
            }
        }

        // accepted by all filters
        return true;
    }

    private void createLogcatViewTable(Composite parent) {
        mTable = new Table(parent, SWT.FULL_SELECTION | SWT.MULTI);

        mTable.setLayoutData(new GridData(GridData.FILL_BOTH));
        mTable.getHorizontalBar().setVisible(true);

        /** Columns to show in the table. */
        String[] properties = {
                "Level",
                "Time",
                "PID",
                "TID",
                "Application",
                "Tag",
                "Text",
        };

        /** The sampleText for each column is used to determine the default widths
         * for each column. The contents do not matter, only their lengths are needed. */
        String[] sampleText = {
                "    ",
                "    00-00 00:00:00.0000 ",
                "    0000",
                "    0000",
                "    com.android.launcher",
                "    SampleTagText",
                "    Log Message field should be pretty long by default. As long as possible for correct display on Mac.",
        };

        for (int i = 0; i < properties.length; i++) {
            TableHelper.createTableColumn(mTable,
                    properties[i],                      /* Column title */
                    SWT.LEFT,                           /* Column Style */
                    sampleText[i],                      /* String to compute default col width */
                    getColPreferenceKey(properties[i]), /* Preference Store key for this column */
                    mPrefStore);
        }

        // don't zebra stripe the table: When the buffer is full, and scroll lock is on, having
        // zebra striping means that the background could keep changing depending on the number
        // of new messages added to the bottom of the log.
        mTable.setLinesVisible(false);
        mTable.setHeaderVisible(true);

        // Set the row height to be sufficient enough to display the current font.
        // This is not strictly necessary, except that on WinXP, the rows showed up clipped. So
        // we explicitly set it to be sure.
        mTable.addListener(SWT.MeasureItem, new Listener() {
            @Override
            public void handleEvent(Event event) {
                event.height = event.gc.getFontMetrics().getHeight();
            }
        });

        // Update the label provider whenever the text column's width changes
        TableColumn textColumn = mTable.getColumn(properties.length - 1);
        textColumn.addControlListener(new ControlAdapter() {
            @Override
            public void controlResized(ControlEvent event) {
                recomputeWrapWidth();
            }
        });

        addRightClickMenu(mTable);
        initDoubleClickListener();
        recomputeWrapWidth();

        mTable.addDisposeListener(new DisposeListener() {
            @Override
            public void widgetDisposed(DisposeEvent arg0) {
                dispose();
            }
        });

        final ScrollBar vbar = mTable.getVerticalBar();
        mScrollBarSelectionListener = new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (!mAutoScrollLock) {
                    return;
                }

                // thumb + selection < max => bar is not at the bottom.
                // We subtract an arbitrary amount (thumbSize/2) from this difference to allow
                // for cases like half a line being displayed at the end from affecting this
                // calculation. The thumbSize/2 number seems to work experimentally across
                // Linux/Mac & Windows, but might possibly need tweaking.
                int diff = vbar.getThumb() + vbar.getSelection() - vbar.getMaximum();
                boolean isAtBottom = Math.abs(diff) < vbar.getThumb() / 2;

                if (isAtBottom != mShouldScrollToLatestLog) {
                    setScrollToLatestLog(isAtBottom);
                    mScrollLockCheckBox.setSelection(isAtBottom);
                }
            }
        };
        startScrollBarMonitor(vbar);

        // Explicitly set the values to use for the scroll bar. In particular, we want these values
        // to have a high enough accuracy that even small movements of the scroll bar have an
        // effect on the selection. The auto scroll lock detection assumes that the scroll bar is
        // at the bottom iff selection + thumb == max.
        final int MAX = 10000;
        final int THUMB = 10;
        vbar.setValues(MAX - THUMB, // selection
                0,                  // min
                MAX,                // max
                THUMB,              // thumb
                1,                  // increment
                THUMB);             // page increment
    }

    private void startScrollBarMonitor(ScrollBar vbar) {
        synchronized (mScrollBarSelectionListenerLock) {
            if (!mScrollBarListenerSet) {
                mScrollBarListenerSet = true;
                vbar.addSelectionListener(mScrollBarSelectionListener);
            }
        }
    }

    private void stopScrollBarMonitor(ScrollBar vbar) {
        synchronized (mScrollBarSelectionListenerLock) {
            if (mScrollBarListenerSet) {
                mScrollBarListenerSet = false;
                vbar.removeSelectionListener(mScrollBarSelectionListener);
            }
        }
    }

    /** Setup menu to be displayed when right clicking a log message. */
    private void addRightClickMenu(final Table table) {
        // This action will pop up a create filter dialog pre-populated with current selection
        final Action filterAction = new Action("Filter similar messages...") {
            @Override
            public void run() {
                List<LogCatMessage> selectedMessages = getSelectedLogCatMessages();
                if (selectedMessages.size() == 0) {
                    addNewFilter();
                } else {
                    LogCatMessage m = selectedMessages.get(0);
                    addNewFilter(m.getTag(), m.getMessage(), m.getPid(), m.getAppName(),
                            m.getLogLevel());
                }
            }
        };

        final Action findAction = new Action("Find...") {
            @Override
            public void run() {
                showFindDialog();
            };
        };

        final MenuManager mgr = new MenuManager();
        mgr.add(filterAction);
        mgr.add(findAction);
        final Menu menu = mgr.createContextMenu(table);

        table.addListener(SWT.MenuDetect, new Listener() {
            @Override
            public void handleEvent(Event event) {
                Point pt = table.getDisplay().map(null, table, new Point(event.x, event.y));
                Rectangle clientArea = table.getClientArea();

                // The click location is in the header if it is between
                // clientArea.y and clientArea.y + header height
                boolean header = pt.y > clientArea.y
                                    && pt.y < (clientArea.y + table.getHeaderHeight());

                // Show the menu only if it is not inside the header
                table.setMenu(header ? null : menu);
            }
        });
    }

    public void recomputeWrapWidth() {
        if (mTable == null || mTable.isDisposed()) {
            return;
        }

        // get width of the last column (log message)
        TableColumn tc = mTable.getColumn(mTable.getColumnCount() - 1);
        int colWidth = tc.getWidth();

        // get font width
        GC gc = new GC(tc.getParent());
        gc.setFont(mFont);
        int avgCharWidth = gc.getFontMetrics().getAverageCharWidth();
        gc.dispose();

        int MIN_CHARS_PER_LINE = 50;    // show atleast these many chars per line
        mWrapWidthInChars = Math.max(colWidth/avgCharWidth, MIN_CHARS_PER_LINE);

        int OFFSET_AT_END_OF_LINE = 10; // leave some space at the end of the line
        mWrapWidthInChars -= OFFSET_AT_END_OF_LINE;
    }

    private void setScrollToLatestLog(boolean scroll) {
        mShouldScrollToLatestLog = scroll;
        if (scroll) {
            scrollToLatestLog();
        }
    }

    private String getColPreferenceKey(String field) {
        return LOGCAT_VIEW_COLSIZE_PREFKEY_PREFIX + field;
    }

    private Font getFontFromPrefStore() {
        FontData fd = PreferenceConverter.getFontData(mPrefStore,
                LogCatPanel.LOGCAT_VIEW_FONT_PREFKEY);
        return new Font(Display.getDefault(), fd);
    }

    private Color getColorFromPrefStore(String key) {
        RGB rgb = PreferenceConverter.getColor(mPrefStore, key);
        return new Color(Display.getDefault(), rgb);
    }

    private void setupDefaults() {
        int defaultFilterIndex = 0;
        mFiltersTableViewer.getTable().setSelection(defaultFilterIndex);

        filterSelectionChanged();
    }

    /**
     * Perform all necessary updates whenever a filter is selected (by user or programmatically).
     */
    private void filterSelectionChanged() {
        int idx = mFiltersTableViewer.getTable().getSelectionIndex();
        if (idx == -1) {
            /* One of the filters should always be selected.
             * On Linux, there is no way to deselect an item.
             * On Mac, clicking inside the list view, but not an any item will result
             * in all items being deselected. In such a case, we simply reselect the
             * first entry. */
            idx = 0;
            mFiltersTableViewer.getTable().setSelection(idx);
        }

        mCurrentSelectedFilterIndex = idx;

        resetUnreadCountForAllFilters();
        updateFiltersToolBar();
        updateAppliedFilters();
    }

    private void resetUnreadCountForAllFilters() {
        for (LogCatFilterData fd: mLogCatFilterData.values()) {
            fd.resetUnreadCount();
        }
        refreshFiltersTable();
    }

    private void updateFiltersToolBar() {
        /* The default filter at index 0 can neither be edited, nor removed. */
        boolean en = mCurrentSelectedFilterIndex != DEFAULT_FILTER_INDEX;
        mEditFilterToolItem.setEnabled(en);
        mDeleteFilterToolItem.setEnabled(en);
    }

    private void updateAppliedFilters() {
        mCurrentFilters = getFiltersToApply();
        reloadLogBuffer();
    }

    private List<LogCatFilter> getFiltersToApply() {
        /* list of filters to apply = saved filter + live filters */
        List<LogCatFilter> filters = new ArrayList<LogCatFilter>();

        if (mCurrentSelectedFilterIndex != DEFAULT_FILTER_INDEX) {
            filters.add(getSelectedSavedFilter());
        }

        filters.addAll(getCurrentLiveFilters());
        return filters;
    }

    private List<LogCatFilter> getCurrentLiveFilters() {
        return LogCatFilter.fromString(
                mLiveFilterText.getText(),                                  /* current query */
                LogLevel.getByString(mLiveFilterLevelCombo.getText()));     /* current log level */
    }

    private LogCatFilter getSelectedSavedFilter() {
        return mLogCatFilters.get(mCurrentSelectedFilterIndex);
    }

    @Override
    public void setFocus() {
    }

    @Override
    public void bufferChanged(List<LogCatMessage> addedMessages,
            List<LogCatMessage> deletedMessages) {
        updateUnreadCount(addedMessages);
        refreshFiltersTable();

        synchronized (mLogBuffer) {
            addedMessages = applyCurrentFilters(addedMessages);
            deletedMessages = applyCurrentFilters(deletedMessages);

            mLogBuffer.addAll(addedMessages);
            mDeletedLogCount += deletedMessages.size();
        }

        refreshLogCatTable();
    }

    private void reloadLogBuffer() {
        mTable.removeAll();

        synchronized (mLogBuffer) {
            mLogBuffer.clear();
            mDeletedLogCount = 0;
        }

        if (mReceiver == null || mReceiver.getMessages() == null) {
            return;
        }

        List<LogCatMessage> addedMessages = mReceiver.getMessages().getAllMessages();
        List<LogCatMessage> deletedMessages = Collections.emptyList();
        bufferChanged(addedMessages, deletedMessages);
    }

    /**
     * When new messages are received, and they match a saved filter, update
     * the unread count associated with that filter.
     * @param receivedMessages list of new messages received
     */
    private void updateUnreadCount(List<LogCatMessage> receivedMessages) {
        for (int i = 0; i < mLogCatFilters.size(); i++) {
            if (i == mCurrentSelectedFilterIndex) {
                /* no need to update unread count for currently selected filter */
                continue;
            }
            LogCatFilter f = mLogCatFilters.get(i);
            LogCatFilterData fd = mLogCatFilterData.get(f);
            fd.updateUnreadCount(receivedMessages);
        }
    }

    private void refreshFiltersTable() {
        Display.getDefault().asyncExec(new Runnable() {
            @Override
            public void run() {
                if (mFiltersTableViewer.getTable().isDisposed()) {
                    return;
                }
                mFiltersTableViewer.refresh();
            }
        });
    }

    /** Task currently submitted to {@link Display#asyncExec} to be run in UI thread. */
    private LogCatTableRefresherTask mCurrentRefresher;

    /**
     * Refresh the logcat table asynchronously from the UI thread.
     * This method adds a new async refresh only if there are no pending refreshes for the table.
     * Doing so eliminates redundant refresh threads from being queued up to be run on the
     * display thread.
     */
    private void refreshLogCatTable() {
        synchronized (this) {
            if (mCurrentRefresher == null) {
                mCurrentRefresher = new LogCatTableRefresherTask();
                Display.getDefault().asyncExec(mCurrentRefresher);
            }
        }
    }

    /**
     * The {@link LogCatTableRefresherTask} takes care of refreshing the table with the
     * new log messages that have been received. Since the log behaves like a circular buffer,
     * the first step is to remove items from the top of the table (if necessary). This step
     * is complicated by the fact that a single log message may span multiple rows if the message
     * was wrapped. Once the deleted items are removed, the new messages are added to the bottom
     * of the table. If scroll lock is enabled, the item that was original visible is made visible
     * again, if not, the last item is made visible.
     */
    private class LogCatTableRefresherTask implements Runnable {
        @Override
        public void run() {
            if (mTable.isDisposed()) {
                return;
            }
            synchronized (LogCatPanel.this) {
                mCurrentRefresher = null;
            }

            // Current topIndex so that it can be restored if scroll locked.
            int topIndex = mTable.getTopIndex();

            mTable.setRedraw(false);

            // the scroll bar should only listen to user generated scroll events, not the
            // scroll events that happen due to the addition of logs
            stopScrollBarMonitor(mTable.getVerticalBar());

            // Obtain the list of new messages, and the number of deleted messages.
            List<LogCatMessage> newMessages;
            int deletedMessageCount;
            synchronized (mLogBuffer) {
                newMessages = new ArrayList<LogCatMessage>(mLogBuffer);
                mLogBuffer.clear();

                deletedMessageCount = mDeletedLogCount;
                mDeletedLogCount = 0;

                mFindTarget.scrollBy(deletedMessageCount);
            }

            int originalItemCount = mTable.getItemCount();

            // Remove entries from the start of the table if they were removed in the log buffer
            // This is complicated by the fact that a single message may span multiple TableItems
            // if it was word-wrapped.
            deletedMessageCount -= removeFromTable(mTable, deletedMessageCount);

            // Compute number of table items that were deleted from the table.
            int deletedItemCount = originalItemCount - mTable.getItemCount();

            // If there are more messages to delete (after deleting messages from the table),
            // then delete them from the start of the newly added messages list
            if (deletedMessageCount > 0) {
                assert deletedMessageCount < newMessages.size();
                for (int i = 0; i < deletedMessageCount; i++) {
                    newMessages.remove(0);
                }
            }

            // Add the remaining messages to the table.
            for (LogCatMessage m: newMessages) {
                List<String> wrappedMessageList = wrapMessage(m.getMessage(), mWrapWidthInChars);
                Color c = getForegroundColor(m);
                for (int i = 0; i < wrappedMessageList.size(); i++) {
                    TableItem item = new TableItem(mTable, SWT.NONE);

                    if (i == 0) {
                        // Only set the message data in the first item. This allows code that
                        // examines the table item data (such as copy selection) to distinguish
                        // between real messages versus lines that are really just wrapped
                        // content from the previous message.
                        item.setData(m);

                        item.setText(new String[] {
                                Character.toString(m.getLogLevel().getPriorityLetter()),
                                m.getTime(),
                                m.getPid(),
                                m.getTid(),
                                m.getAppName(),
                                m.getTag(),
                                wrappedMessageList.get(i)
                        });
                    } else {
                        item.setText(new String[] {
                                "", "", "", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                                "", "", "", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                                wrappedMessageList.get(i)
                        });
                    }
                    item.setForeground(c);
                    item.setFont(mFont);
                }
            }

            if (mShouldScrollToLatestLog) {
                scrollToLatestLog();
            } else {
                // If scroll locked, show the same item that was original visible in the table.
                int index = Math.max(topIndex - deletedItemCount, 0);
                mTable.setTopIndex(index);
            }

            mTable.setRedraw(true);

            // re-enable listening to scroll bar events, but do so in a separate thread to make
            // sure that the current task (LogCatRefresherTask) has completed first
            Display.getDefault().asyncExec(new Runnable() {
                @Override
                public void run() {
                    if (!mTable.isDisposed()) {
                        startScrollBarMonitor(mTable.getVerticalBar());
                    }
                }
            });
        }

        /**
         * Removes given number of messages from the table, starting at the top of the table.
         * Note that the number of messages deleted is not equal to the number of rows
         * deleted since a single message could span multiple rows. This method first calculates
         * the number of rows that correspond to the number of messages to delete, and then
         * removes all those rows.
         * @param table table from which messages should be removed
         * @param msgCount number of messages to be removed
         * @return number of messages that were actually removed
         */
        private int removeFromTable(Table table, int msgCount) {
            int deletedMessageCount = 0; // # of messages that have been deleted
            int lastItemToDelete = 0;    // index of the last item that should be deleted

            while (deletedMessageCount < msgCount && lastItemToDelete < table.getItemCount()) {
                // only rows that begin a message have their item data set
                TableItem item = table.getItem(lastItemToDelete);
                if (item.getData() != null) {
                    deletedMessageCount++;
                }

                lastItemToDelete++;
            }

            // If there are any table items left over at the end that are wrapped over from the
            // previous message, mark them for deletion as well.
            if (lastItemToDelete < table.getItemCount()
                    && table.getItem(lastItemToDelete).getData() == null) {
                lastItemToDelete++;
            }

            table.remove(0, lastItemToDelete - 1);

            return deletedMessageCount;
        }
    }

    /** Scroll to the last line. */
    private void scrollToLatestLog() {
        if (!mTable.isDisposed()) {
            mTable.setTopIndex(mTable.getItemCount() - 1);
        }
    }

    /**
     * Splits the message into multiple lines if the message length exceeds given width.
     * If the message was split, then a wrap character \u23ce is appended to the end of all
     * lines but the last one.
     */
    private List<String> wrapMessage(String msg, int wrapWidth) {
        if (msg.length() < wrapWidth) {
            return Collections.singletonList(msg);
        }

        List<String> wrappedMessages = new ArrayList<String>();

        int offset = 0;
        int len = msg.length();

        while (len > 0) {
            int copylen = Math.min(wrapWidth, len);
            String s = msg.substring(offset, offset + copylen);

            offset += copylen;
            len -= copylen;

            if (len > 0) { // if there are more lines following, then append a wrap marker
                s += " \u23ce"; //$NON-NLS-1$
            }

            wrappedMessages.add(s);
        }

        return wrappedMessages;
    }

    private Color getForegroundColor(LogCatMessage m) {
        LogLevel l = m.getLogLevel();

        if (l.equals(LogLevel.VERBOSE)) {
            return mVerboseColor;
        } else if (l.equals(LogLevel.INFO)) {
            return mInfoColor;
        } else if (l.equals(LogLevel.DEBUG)) {
            return mDebugColor;
        } else if (l.equals(LogLevel.ERROR)) {
            return mErrorColor;
        } else if (l.equals(LogLevel.WARN)) {
            return mWarnColor;
        } else if (l.equals(LogLevel.ASSERT)) {
            return mAssertColor;
        }

        return mVerboseColor;
    }

    private List<ILogCatMessageSelectionListener> mMessageSelectionListeners;

    private void initDoubleClickListener() {
        mMessageSelectionListeners = new ArrayList<ILogCatMessageSelectionListener>(1);

        mTable.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetDefaultSelected(SelectionEvent arg0) {
                List<LogCatMessage> selectedMessages = getSelectedLogCatMessages();
                if (selectedMessages.size() == 0) {
                    return;
                }

                for (ILogCatMessageSelectionListener l : mMessageSelectionListeners) {
                    l.messageDoubleClicked(selectedMessages.get(0));
                }
            }
        });
    }

    public void addLogCatMessageSelectionListener(ILogCatMessageSelectionListener l) {
        mMessageSelectionListeners.add(l);
    }

    private ITableFocusListener mTableFocusListener;

    /**
     * Specify the listener to be called when the logcat view gets focus. This interface is
     * required by DDMS to hook up the menu items for Copy and Select All.
     * @param listener listener to be notified when logcat view is in focus
     */
    public void setTableFocusListener(ITableFocusListener listener) {
        mTableFocusListener = listener;

        final IFocusedTableActivator activator = new IFocusedTableActivator() {
            @Override
            public void copy(Clipboard clipboard) {
                copySelectionToClipboard(clipboard);
            }

            @Override
            public void selectAll() {
                mTable.selectAll();
            }
        };

        mTable.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                mTableFocusListener.focusGained(activator);
            }

            @Override
            public void focusLost(FocusEvent e) {
                mTableFocusListener.focusLost(activator);
            }
        });
    }

    /** Copy all selected messages to clipboard. */
    public void copySelectionToClipboard(Clipboard clipboard) {
        StringBuilder sb = new StringBuilder();

        for (LogCatMessage m : getSelectedLogCatMessages()) {
            sb.append(m.toString());
            sb.append('\n');
        }

        if (sb.length() > 0) {
            clipboard.setContents(
                    new Object[] {sb.toString()},
                    new Transfer[] {TextTransfer.getInstance()}
                    );
        }
    }

    /** Select all items in the logcat table. */
    public void selectAll() {
        mTable.selectAll();
    }

    private void dispose() {
        if (mFont != null && !mFont.isDisposed()) {
            mFont.dispose();
        }

        if (mVerboseColor != null && !mVerboseColor.isDisposed()) {
            disposeMessageColors();
        }
    }

    private void disposeMessageColors() {
        mVerboseColor.dispose();
        mDebugColor.dispose();
        mInfoColor.dispose();
        mWarnColor.dispose();
        mErrorColor.dispose();
        mAssertColor.dispose();
    }

    private class LogcatFindTarget extends AbstractBufferFindTarget {
        @Override
        public void selectAndReveal(int index) {
            mTable.deselectAll();
            mTable.select(index);
            mTable.showSelection();
        }

        @Override
        public int getItemCount() {
            return mTable.getItemCount();
        }

        @Override
        public String getItem(int index) {
            Object data = mTable.getItem(index).getData();
            if (data != null) {
                return data.toString();
            }

            return null;
        }

        @Override
        public int getStartingIndex() {
            // start searches from current selection if present, otherwise from the tail end
            // of the buffer
            int s = mTable.getSelectionIndex();
            if (s != -1) {
                return s;
            } else {
                return getItemCount() - 1;
            }
        };
    };

    private FindDialog mFindDialog;
    private LogcatFindTarget mFindTarget = new LogcatFindTarget();
    public void showFindDialog() {
        if (mFindDialog != null) {
            // if the dialog is already displayed
            return;
        }

        mFindDialog = new FindDialog(Display.getDefault().getActiveShell(), mFindTarget);
        mFindDialog.open(); // blocks until find dialog is closed
        mFindDialog = null;
    }
}

/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.eclipse.org/org/documents/epl-v10.php
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * References:
 * Based on the SWT snippet example at
 * http://dev.eclipse.org/viewcvs/viewvc.cgi/org.eclipse.swt.snippets/src/org/eclipse/swt/snippets/Snippet354.java?view=co
 */

package com.android.menubar;


import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;

import java.lang.reflect.Method;

public class MenuBarEnhancer37 implements IMenuBarEnhancer {

    private static final int kAboutMenuItem = -1;           // SWT.ID_ABOUT       in SWT 3.7
    private static final int kPreferencesMenuItem = -2;     // SWT.ID_PREFERENCES in SWT 3.7
    private static final int kQuitMenuItem = -6;            // SWT.ID_QUIT        in SWT 3.7

    public MenuBarEnhancer37() {
    }

    @Override
    public MenuBarMode getMenuBarMode() {
        return MenuBarMode.MAC_OS;
    }

    /**
     * Setup the About and Preferences native menut items with the
     * given application name and links them to the callback.
     *
     * @param appName The application name.
     * @param display The SWT display. Must not be null.
     * @param callbacks The callbacks invoked by the menus.
     */
    @Override
    public void setupMenu(
            String appName,
            Display display,
            IMenuBarCallback callbacks) {

        try {
            // Initialize the menuItems.
            initialize(display, appName, callbacks);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        // Schedule disposal of callback object
        display.disposeExec(new Runnable() {
            @Override
            public void run() {
            }
        });
    }

    /**
     * Checks whether the required SWT 3.7 APIs are available.
     * <br/>
     * Calling this will load the class, which is OK since this class doesn't
     * directly use any SWT 3.7 API -- instead it uses reflection so that the
     * code can be loaded under SWT 3.6.
     *
     * @param display The current SWT display.
     * @return True if the SWT 3.7 API are available and this enhancer can be used.
     */
    public static boolean isSupported(Display display) {
        try {
            Object sysMenu = call0(display, "getSystemMenu");
            if (sysMenu instanceof Menu) {
                return findMenuById((Menu)sysMenu, kPreferencesMenuItem) != null &&
                       findMenuById((Menu)sysMenu, kAboutMenuItem) != null;
            }
        } catch (Exception ignore) {}
        return false;
    }

    private void initialize(
            Display display,
            String appName,
            final IMenuBarCallback callbacks)
                    throws Exception {
        Object sysMenu = call0(display, "getSystemMenu");
        if (sysMenu instanceof Menu) {
            MenuItem menu = findMenuById((Menu)sysMenu, kPreferencesMenuItem);
            if (menu != null) {
                menu.addSelectionListener(new SelectionAdapter() {
                    @Override
                    public void widgetSelected(SelectionEvent event) {
                        callbacks.onPreferencesMenuSelected();
                    }
                });
            }

            menu = findMenuById((Menu)sysMenu, kAboutMenuItem);
            if (menu != null) {
                menu.addSelectionListener(new SelectionAdapter() {
                    @Override
                    public void widgetSelected(SelectionEvent event) {
                        callbacks.onAboutMenuSelected();
                    }
                });
                menu.setText("About " + appName);
            }

            menu = findMenuById((Menu)sysMenu, kQuitMenuItem);
            if (menu != null) {
                // We already support the "quit" operation, no need for an extra handler here.
                menu.setText("Quit " + appName);
            }

        }
    }

    private static Object call0(Object obj, String method) {
        try {
            Method m = obj.getClass().getMethod(method, (Class<?>[])null);
            if (m != null) {
                return m.invoke(obj, (Object[])null);
            }
        } catch (Exception ignore) {}
        return null;
    }

    private static MenuItem findMenuById(Menu menu, int id) {
        MenuItem[] items = menu.getItems();
        for (int i = items.length - 1; i >= 0; i--) {
            MenuItem item = items[i];
            Object menuId = call0(item, "getID");
            if (menuId instanceof Integer) {
                if (((Integer) menuId).intValue() == id) {
                    return item;
                }
            }
        }
        return null;
    }
}

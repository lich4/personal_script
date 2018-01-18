/*
 * Copyright (C) 2011 The Android Open Source Project
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
 */

package com.android.menubar;

import com.android.menubar.IMenuBarEnhancer.MenuBarMode;

import org.eclipse.jface.action.IAction;
import org.eclipse.jface.action.IMenuManager;
import org.eclipse.jface.action.Separator;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;


/**
 * On Mac, {@link MenuBarEnhancer#setupMenu} plugs a listener on the About and the
 * Preferences menu items of the standard "application" menu in the menu bar.
 * On Windows or Linux, it adds relevant items to a given {@link Menu} linked to
 * the same listeners.
 */
public final class MenuBarEnhancer {

    private MenuBarEnhancer() {
    }

    /**
     * Creates an instance of {@link IMenuBarEnhancer} specific to the current platform
     * and invoke its {@link IMenuBarEnhancer#setupMenu} to updates the menu bar.
     * <p/>
     * Depending on the platform, this will either hook into the existing About menu item
     * and a Preferences or Options menu item or add new ones to the given {@code swtMenu}.
     * Depending on the platform, the menu items might be decorated with the
     * given {@code appName}.
     * <p/>
     * Potential errors are reported through {@link IMenuBarCallback}.
     *
     * @param appName Name used for the About menu item and similar. Must not be null.
     * @param swtMenu For non-mac platform this is the menu where the "About" and
     *          the "Options" menu items are created. Typically the menu might be
     *          called "Tools". Must not be null.
     * @param callbacks Callbacks called when "About" and "Preferences" menu items are invoked.
     *          Must not be null.
     * @return An actual {@link IMenuBarEnhancer} implementation. Can be null on failure.
     *          This is currently not of any use for the caller but is left in case
     *          we want to expand the functionality later.
     */
    public static IMenuBarEnhancer setupMenu(
            String appName,
            final Menu swtMenu,
            IMenuBarCallback callbacks) {

        IMenuBarEnhancer enhancer = getEnhancer(callbacks, swtMenu.getDisplay());

        // Default implementation for generic platforms
        if (enhancer == null) {
            enhancer = getGenericEnhancer(swtMenu);
        }

        try {
            enhancer.setupMenu(appName, swtMenu.getDisplay(), callbacks);
        } catch (Exception e) {
            // If the enhancer failed, try to fall back on the generic one
            if (enhancer.getMenuBarMode() != MenuBarMode.GENERIC) {
                enhancer = getGenericEnhancer(swtMenu);
                try {
                    enhancer.setupMenu(appName, swtMenu.getDisplay(), callbacks);
                } catch (Exception e2) {
                    callbacks.printError("SWTMenuBar failed: %s", e2.toString());
                    return null;
                }
            }
        }
        return enhancer;
    }

    private static IMenuBarEnhancer getGenericEnhancer(final Menu swtMenu) {
        IMenuBarEnhancer enhancer;
        enhancer = new IMenuBarEnhancer() {

            @Override
            public MenuBarMode getMenuBarMode() {
                return MenuBarMode.GENERIC;
            }

            @Override
            public void setupMenu(
                    String appName,
                    Display display,
                    final IMenuBarCallback callbacks) {
                if (swtMenu.getItemCount() > 0) {
                    new MenuItem(swtMenu, SWT.SEPARATOR);
                }

                // Note: we use "Preferences" on Mac and "Options" on Windows/Linux.
                final MenuItem pref = new MenuItem(swtMenu, SWT.NONE);
                pref.setText("&Options...");

                final MenuItem about = new MenuItem(swtMenu, SWT.NONE);
                about.setText("&About...");

                pref.addSelectionListener(new SelectionAdapter() {
                    @Override
                    public void widgetSelected(SelectionEvent e) {
                        try {
                            pref.setEnabled(false);
                            callbacks.onPreferencesMenuSelected();
                            super.widgetSelected(e);
                        } finally {
                            pref.setEnabled(true);
                        }
                    }
                });

                about.addSelectionListener(new SelectionAdapter() {
                    @Override
                    public void widgetSelected(SelectionEvent e) {
                        try {
                            about.setEnabled(false);
                            callbacks.onAboutMenuSelected();
                            super.widgetSelected(e);
                        } finally {
                            about.setEnabled(true);
                        }
                    }
                });
            }
        };
        return enhancer;
    }


    public static IMenuBarEnhancer setupMenuManager(
            String appName,
            Display display,
            final IMenuManager menuManager,
            final IAction aboutAction,
            final IAction preferencesAction,
            final IAction quitAction) {

        IMenuBarCallback callbacks = new IMenuBarCallback() {
            @Override
            public void printError(String format, Object... args) {
                System.err.println(String.format(format, args));
            }

            @Override
            public void onPreferencesMenuSelected() {
                if (preferencesAction != null) {
                    preferencesAction.run();
                }
            }

            @Override
            public void onAboutMenuSelected() {
                if (aboutAction != null) {
                    aboutAction.run();
                }
            }
        };

        IMenuBarEnhancer enhancer = getEnhancer(callbacks, display);

        // Default implementation for generic platforms
        if (enhancer == null) {
            enhancer = new IMenuBarEnhancer() {

                @Override
                public MenuBarMode getMenuBarMode() {
                    return MenuBarMode.GENERIC;
                }

                @Override
                public void setupMenu(
                        String appName,
                        Display display,
                        final IMenuBarCallback callbacks) {
                    if (!menuManager.isEmpty()) {
                        menuManager.add(new Separator());
                    }

                    if (aboutAction != null) {
                        menuManager.add(aboutAction);
                    }
                    if (preferencesAction != null) {
                        menuManager.add(preferencesAction);
                    }
                    if (quitAction != null) {
                        if (aboutAction != null || preferencesAction != null) {
                            menuManager.add(new Separator());
                        }
                        menuManager.add(quitAction);
                    }
                }
            };
        }

        enhancer.setupMenu(appName, display, callbacks);
        return enhancer;
    }

    private static IMenuBarEnhancer getEnhancer(IMenuBarCallback callbacks, Display display) {
        IMenuBarEnhancer enhancer = null;
        String p = SWT.getPlatform();
        String className = null;
        if ("cocoa".equals(p)) {                                                  //$NON-NLS-1$
            className = "com.android.menubar.internal.MenuBarEnhancerCocoa";      //$NON-NLS-1$

            if (SWT.getVersion() >= 3700 && MenuBarEnhancer37.isSupported(display)) {
                className = MenuBarEnhancer37.class.getName();
            }
        }

        if (System.getenv("DEBUG_SWTMENUBAR") != null) {
            callbacks.printError("DEBUG SwtMenuBar: SWT=%1$s, class=%2$s", p, className);
        }

        if (className != null) {
            try {
                Class<?> clazz = Class.forName(className);
                enhancer = (IMenuBarEnhancer) clazz.newInstance();
            } catch (Exception e) {
                // Log an error and fallback on the default implementation.
                callbacks.printError(
                        "Failed to instantiate %1$s: %2$s",                       //$NON-NLS-1$
                        className,
                        e.toString());
            }
        }
        return enhancer;
    }
}

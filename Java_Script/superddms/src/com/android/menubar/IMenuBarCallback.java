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



/**
 * Callbacks used by {@link IMenuBarEnhancer}.
 */
public interface IMenuBarCallback {
    /**
     * Invoked when the About menu item is selected by the user.
     */
    abstract public void onAboutMenuSelected();

    /**
     * Invoked when the Preferences or Options menu item is selected by the user.
     */
    abstract public void onPreferencesMenuSelected();

    /**
     * Used by the enhancer implementations to report errors.
     *
     * @param format A printf-like format string.
     * @param args The parameters for the printf-like format string.
     */
    abstract public void printError(String format, Object...args);
}

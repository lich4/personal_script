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

import com.android.ddmlib.logcat.LogCatFilter;

import org.eclipse.jface.viewers.IStructuredContentProvider;
import org.eclipse.jface.viewers.Viewer;

import java.util.List;

/**
 * A JFace content provider for logcat filter list, used in {@link LogCatPanel}.
 */
public final class LogCatFilterContentProvider implements IStructuredContentProvider {
    @Override
    public void dispose() {
    }

    @Override
    public void inputChanged(Viewer arg0, Object arg1, Object arg2) {
    }

    /**
     * Obtain the list of filters currently in use.
     * @param model list of {@link LogCatFilter}'s
     * @return array of {@link LogCatFilter} objects, or null.
     */
    @Override
    public Object[] getElements(Object model) {
        return ((List<?>) model).toArray();
    }
}

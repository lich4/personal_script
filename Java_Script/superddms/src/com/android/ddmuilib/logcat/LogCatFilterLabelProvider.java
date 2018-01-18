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

import org.eclipse.jface.viewers.ITableLabelProvider;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.swt.graphics.Image;

import java.util.Map;

/**
 * A JFace label provider for the LogCat filters. It expects elements of type
 * {@link LogCatFilter}.
 */
public final class LogCatFilterLabelProvider extends LabelProvider implements ITableLabelProvider {
    private Map<LogCatFilter, LogCatFilterData> mFilterData;

    public LogCatFilterLabelProvider(Map<LogCatFilter, LogCatFilterData> filterData) {
        mFilterData = filterData;
    }

    @Override
    public Image getColumnImage(Object arg0, int arg1) {
        return null;
    }

    /**
     * Implements {@link ITableLabelProvider#getColumnText(Object, int)}.
     * @param element an instance of {@link LogCatFilter}
     * @param index index of the column
     * @return text to use in the column
     */
    @Override
    public String getColumnText(Object element, int index) {
        if (!(element instanceof LogCatFilter)) {
            return null;
        }

        LogCatFilter f = (LogCatFilter) element;
        LogCatFilterData fd = mFilterData.get(f);

        if (fd != null && fd.getUnreadCount() > 0) {
            return String.format("%s (%d)", f.getName(), fd.getUnreadCount());
        } else {
            return f.getName();
        }
    }
}

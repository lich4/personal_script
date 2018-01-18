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

import com.android.ddmlib.NativeStackCallInfo;

import org.eclipse.jface.viewers.ITableLabelProvider;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.swt.graphics.Image;

public class NativeStackLabelProvider extends LabelProvider implements ITableLabelProvider {
    @Override
    public Image getColumnImage(Object arg0, int arg1) {
        return null;
    }

    @Override
    public String getColumnText(Object element, int index) {
        if (element instanceof NativeStackCallInfo) {
            return getResolvedStackTraceColumnText((NativeStackCallInfo) element, index);
        }

        if (element instanceof Long) {
            // if the addresses have not been resolved, then just display the
            // addresses alone
            return getStackAddressColumnText((Long) element, index);
        }

        return null;
    }

    public String getResolvedStackTraceColumnText(NativeStackCallInfo info, int index) {
        switch (index) {
        case 0:
            return String.format("0x%08x", info.getAddress());
        case 1:
            return info.getLibraryName();
        case 2:
            return info.getMethodName();
        case 3:
            return info.getSourceFile();
        case 4:
            int l = info.getLineNumber();
            return l == -1 ? "" : Integer.toString(l);
        }

        return null;
    }

    private String getStackAddressColumnText(Long address, int index) {
        if (index == 0) {
            return String.format("0x%08x", address);
        }

        return null;
    }
}

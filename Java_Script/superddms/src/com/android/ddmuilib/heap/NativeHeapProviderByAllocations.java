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

import com.android.ddmlib.NativeAllocationInfo;

import org.eclipse.jface.viewers.ILazyTreeContentProvider;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.jface.viewers.Viewer;

import java.util.List;

/**
 * Content Provider for the native heap tree viewer in {@link NativeHeapPanel}.
 * It expects a {@link NativeHeapSnapshot} as input, and provides the list of allocations
 * in the heap dump as content to the UI.
 */
public final class NativeHeapProviderByAllocations implements ILazyTreeContentProvider {
    private TreeViewer mViewer;
    private boolean mDisplayZygoteMemory;
    private NativeHeapSnapshot mNativeHeapDump;

    public NativeHeapProviderByAllocations(TreeViewer viewer, boolean displayZygotes) {
        mViewer = viewer;
        mDisplayZygoteMemory = displayZygotes;
    }

    @Override
    public void dispose() {
    }

    @Override
    public void inputChanged(Viewer viewer, Object oldInput, Object newInput) {
        mNativeHeapDump = (NativeHeapSnapshot) newInput;
    }

    @Override
    public Object getParent(Object arg0) {
        return null;
    }

    @Override
    public void updateChildCount(Object element, int currentChildCount) {
        int childCount = 0;

        if (element == mNativeHeapDump) { // root element
            childCount = getAllocations().size();
        }

        mViewer.setChildCount(element, childCount);
    }

    @Override
    public void updateElement(Object parent, int index) {
        Object item = null;

        if (parent == mNativeHeapDump) { // root element
            item = getAllocations().get(index);
        }

        mViewer.replace(parent, index, item);
        mViewer.setChildCount(item, 0);
    }

    public void displayZygoteMemory(boolean en) {
        mDisplayZygoteMemory = en;
    }

    private List<NativeAllocationInfo> getAllocations() {
        if (mDisplayZygoteMemory) {
            return mNativeHeapDump.getAllocations();
        } else {
            return mNativeHeapDump.getNonZygoteAllocations();
        }
    }
}

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

import org.eclipse.jface.viewers.ILazyTreeContentProvider;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.jface.viewers.Viewer;

import java.util.List;

/**
 * Content Provider for the native heap tree viewer in {@link NativeHeapPanel}.
 * It expects input of type {@link NativeHeapSnapshot}, and provides heap allocations
 * grouped by library to the UI.
 */
public class NativeHeapProviderByLibrary implements ILazyTreeContentProvider {
    private TreeViewer mViewer;
    private boolean mDisplayZygoteMemory;

    public NativeHeapProviderByLibrary(TreeViewer viewer, boolean displayZygotes) {
        mViewer = viewer;
        mDisplayZygoteMemory = displayZygotes;
    }

    @Override
    public void dispose() {
    }

    @Override
    public void inputChanged(Viewer viewer, Object oldInput, Object newInput) {
    }

    @Override
    public Object getParent(Object element) {
        return null;
    }

    @Override
    public void updateChildCount(Object element, int currentChildCount) {
        int childCount = 0;

        if (element instanceof NativeHeapSnapshot) {
            NativeHeapSnapshot snapshot = (NativeHeapSnapshot) element;
            childCount = getLibraryAllocations(snapshot).size();
        } else if (element instanceof NativeLibraryAllocationInfo) {
            NativeLibraryAllocationInfo info = (NativeLibraryAllocationInfo) element;
            childCount = info.getAllocations().size();
        }

        mViewer.setChildCount(element, childCount);
    }

    @Override
    public void updateElement(Object parent, int index) {
        Object item = null;
        int childCount = 0;

        if (parent instanceof NativeHeapSnapshot) { // root element
            NativeHeapSnapshot snapshot = (NativeHeapSnapshot) parent;
            item = getLibraryAllocations(snapshot).get(index);
            childCount = ((NativeLibraryAllocationInfo) item).getAllocations().size();
        } else if (parent instanceof NativeLibraryAllocationInfo) {
            item = ((NativeLibraryAllocationInfo) parent).getAllocations().get(index);
        }

        mViewer.replace(parent, index, item);
        mViewer.setChildCount(item, childCount);
    }

    public void displayZygoteMemory(boolean en) {
        mDisplayZygoteMemory = en;
    }

    private List<NativeLibraryAllocationInfo> getLibraryAllocations(NativeHeapSnapshot snapshot) {
        if (mDisplayZygoteMemory) {
            return snapshot.getAllocationsByLibrary();
        } else {
            return snapshot.getNonZygoteAllocationsByLibrary();
        }
    }
}

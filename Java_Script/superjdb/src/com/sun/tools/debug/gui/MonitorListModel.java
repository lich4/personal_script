/*
 * Copyright (c) 1999, 2011, Oracle and/or its affiliates. All rights reserved.
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */

/*
 * This source code is provided to illustrate the usage of a given feature
 * or technique and has been deliberately simplified. Additional steps
 * required for a production-quality application, such as security checks,
 * input validation and proper error handling, might not be present in
 * this sample code.
 */


package com.sun.tools.debug.gui;

import java.util.*;

import javax.swing.AbstractListModel;

public class MonitorListModel extends AbstractListModel {

    private final List<String> monitors = new ArrayList<String>();

    MonitorListModel(Environment env) {

        // Create listener.
        MonitorListListener listener = new MonitorListListener();
        env.getContextManager().addContextListener(listener);

        //### remove listeners on exit!
    }

    @Override
    public Object getElementAt(int index) {
        return monitors.get(index);
    }

    @Override
    public int getSize() {
        return monitors.size();
    }

    public void add(String expr) {
        monitors.add(expr);
        int newIndex = monitors.size()-1;  // order important
        fireIntervalAdded(this, newIndex, newIndex);
    }

    public void remove(String expr) {
        int index = monitors.indexOf(expr);
        remove(index);
    }

    public void remove(int index) {
        monitors.remove(index);
        fireIntervalRemoved(this, index, index);
    }

    public List<String> monitors() {
        return Collections.unmodifiableList(monitors);
    }

    public Iterator<?> iterator() {
        return monitors().iterator();
    }

    private void invalidate() {
        fireContentsChanged(this, 0, monitors.size()-1);
    }

    private class MonitorListListener implements ContextListener {

        @Override
        public void currentFrameChanged(final CurrentFrameChangedEvent e) {
            invalidate();
        }
    }
}

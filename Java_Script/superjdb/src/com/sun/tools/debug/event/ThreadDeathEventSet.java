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


package com.sun.tools.debug.event;

import com.sun.jdi.*;
import com.sun.jdi.event.*;

public class ThreadDeathEventSet extends AbstractEventSet {

    private static final long serialVersionUID = -8801604712308151331L;

    ThreadDeathEventSet(EventSet jdiEventSet) {
        super(jdiEventSet);
    }

    /**
     * Returns the thread which is terminating.
     *
     * @return a {@link ThreadReference} which mirrors the event's thread in
     * the target VM.
     */
    public ThreadReference getThread() {
        return ((ThreadDeathEvent)oneEvent).thread();
    }

    @Override
    public void notify(JDIListener listener) {
        listener.threadDeath(this);
    }
}

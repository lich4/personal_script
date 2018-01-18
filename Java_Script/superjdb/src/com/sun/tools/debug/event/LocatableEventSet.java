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

/**
 * Abstract event set for events with location and thread.
 */
public abstract class LocatableEventSet extends AbstractEventSet {

    private static final long serialVersionUID = 1027131209997915620L;

    LocatableEventSet(EventSet jdiEventSet) {
        super(jdiEventSet);
    }

    /**
     * Returns the {@link Location} of this mirror. Depending on context
     * and on available debug information, this location will have
     * varying precision.
     *
     * @return the {@link Location} of this mirror.
     */
    public Location getLocation() {
        return ((LocatableEvent)oneEvent).location();
    }

    /**
     * Returns the thread in which this event has occurred.
     *
     * @return a {@link ThreadReference} which mirrors the event's thread in
     * the target VM.
     */
    public ThreadReference getThread() {
        return ((LocatableEvent)oneEvent).thread();
    }
}

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

public class ModificationWatchpointEventSet extends WatchpointEventSet {

    private static final long serialVersionUID = -680889300856154719L;

    ModificationWatchpointEventSet(EventSet jdiEventSet) {
        super(jdiEventSet);
    }

    /**
     * Value that will be assigned to the field when the instruction
     * completes.
     */
    public Value getValueToBe() {
        return ((ModificationWatchpointEvent)oneEvent).valueToBe();
    }

    @Override
    public void notify(JDIListener listener) {
        listener.modificationWatchpoint(this);
    }
}

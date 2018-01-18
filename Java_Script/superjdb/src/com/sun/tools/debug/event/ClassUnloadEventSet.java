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

import com.sun.jdi.event.*;

public class ClassUnloadEventSet extends AbstractEventSet {

    private static final long serialVersionUID = 8370341450345835866L;

    ClassUnloadEventSet(EventSet jdiEventSet) {
        super(jdiEventSet);
    }

    /**
     * Returns the name of the class that has been unloaded.
     */
    public String getClassName() {
        return ((ClassUnloadEvent)oneEvent).className();
    }

    /**
     * Returns the JNI-style signature of the class that has been unloaded.
     */
    public String getClassSignature() {
        return ((ClassUnloadEvent)oneEvent).classSignature();
    }

    @Override
    public void notify(JDIListener listener) {
        listener.classUnload(this);
    }
}

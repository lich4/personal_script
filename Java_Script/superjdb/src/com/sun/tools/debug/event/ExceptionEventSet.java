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

public class ExceptionEventSet extends LocatableEventSet {

    private static final long serialVersionUID = 5328140167954640711L;

    ExceptionEventSet(EventSet jdiEventSet) {
        super(jdiEventSet);
    }

    /**
     * Gets the thrown exception object. The exception object is
     * an instance of java.lang.Throwable or a subclass in the
     * target VM.
     *
     * @return an {@link ObjectReference} which mirrors the thrown object in
     * the target VM.
     */
    public ObjectReference getException() {
        return ((ExceptionEvent)oneEvent).exception();
    }

    /**
     * Gets the location where the exception will be caught. An exception
     * is considered to be caught if, at the point of the throw, the
     * current location is dynamically enclosed in a try statement that
     * handles the exception. (See the JVM specification for details).
     * If there is such a try statement, the catch location is the
     * first code index of the appropriate catch clause.
     * <p>
     * If there are native methods in the call stack at the time of the
     * exception, there are important restrictions to note about the
     * returned catch location. In such cases,
     * it is not possible to predict whether an exception will be handled
     * by some native method on the call stack.
     * Thus, it is possible that exceptions considered uncaught
     * here will, in fact, be handled by a native method and not cause
     * termination of the target VM. Also, it cannot be assumed that the
     * catch location returned here will ever be reached by the throwing
     * thread. If there is
     * a native frame between the current location and the catch location,
     * the exception might be handled and cleared in that native method
     * instead.
     *
     * @return the {@link Location} where the exception will be caught or null if
     * the exception is uncaught.
     */
    public Location getCatchLocation() {
        return ((ExceptionEvent)oneEvent).catchLocation();
    }

    @Override
    public void notify(JDIListener listener) {
        listener.exception(this);
    }
}

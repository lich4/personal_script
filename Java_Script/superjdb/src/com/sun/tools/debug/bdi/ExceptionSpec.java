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


package com.sun.tools.debug.bdi;

import com.sun.jdi.ReferenceType;

public class ExceptionSpec extends EventRequestSpec {

    boolean notifyCaught;
    boolean notifyUncaught;

    ExceptionSpec(EventRequestSpecList specs, ReferenceTypeSpec refSpec,
                  boolean notifyCaught, boolean notifyUncaught)
    {
        super(specs, refSpec);
        this.notifyCaught = notifyCaught;
        this.notifyUncaught = notifyUncaught;
    }

    @Override
    void notifySet(SpecListener listener, SpecEvent evt) {
        listener.exceptionInterceptSet(evt);
    }

    @Override
    void notifyDeferred(SpecListener listener, SpecEvent evt) {
        listener.exceptionInterceptDeferred(evt);
    }

    @Override
    void notifyResolved(SpecListener listener, SpecEvent evt) {
        listener.exceptionInterceptResolved(evt);
    }

    @Override
    void notifyDeleted(SpecListener listener, SpecEvent evt) {
        listener.exceptionInterceptDeleted(evt);
    }

    @Override
    void notifyError(SpecListener listener, SpecErrorEvent evt) {
        listener.exceptionInterceptError(evt);
    }

    /**
     * The 'refType' is known to match.
     */
    @Override
    void resolve(ReferenceType refType) {
        setRequest(refType.virtualMachine().eventRequestManager()
                   .createExceptionRequest(refType,
                                           notifyCaught, notifyUncaught));
    }

    @Override
    public int hashCode() {
        return refSpec.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ExceptionSpec) {
            ExceptionSpec es = (ExceptionSpec)obj;

            return refSpec.equals(es.refSpec);
        } else {
            return false;
        }
    }

    @Override
    public String toString() {
        StringBuffer buffer = new StringBuffer("exception catch ");
        buffer.append(refSpec.toString());
        return buffer.toString();
    }
}

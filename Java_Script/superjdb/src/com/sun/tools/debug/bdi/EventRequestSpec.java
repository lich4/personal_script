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

import com.sun.jdi.*;
import com.sun.jdi.request.EventRequest;

abstract public class EventRequestSpec {

    static final int STATUS_UNRESOLVED = 1;
    static final int STATUS_RESOLVED = 2;
    static final int STATUS_ERROR = 3;

    static final Object specPropertyKey = "spec";

    final EventRequestSpecList specs;
    final ReferenceTypeSpec refSpec;
    EventRequest request = null;

    int status = STATUS_UNRESOLVED;

    EventRequestSpec(EventRequestSpecList specs, ReferenceTypeSpec refSpec) {
        this.specs = specs;
        this.refSpec = refSpec;
    }

    void setRequest(EventRequest request) {
        this.request = request;
        request.putProperty(specPropertyKey, this);
        request.enable();
    }

    /**
     * The 'refType' is known to match.
     */
    abstract void resolve(ReferenceType refType) throws Exception;

    abstract void notifySet(SpecListener listener, SpecEvent evt);
    abstract void notifyDeferred(SpecListener listener, SpecEvent evt);
    abstract void notifyResolved(SpecListener listener, SpecEvent evt);
    abstract void notifyDeleted(SpecListener listener, SpecEvent evt);
    abstract void notifyError(SpecListener listener, SpecErrorEvent evt);

    /**
     * The 'refType' is known to match.
     */
    void resolveNotify(ReferenceType refType) {
        try {
            resolve(refType);
            status = STATUS_RESOLVED;
            specs.notifyResolved(this);
        } catch(Exception exc) {
            status = STATUS_ERROR;
            specs.notifyError(this, exc);
        }
    }

    /**
     * See if 'refType' matches and resolve.
     */
    void attemptResolve(ReferenceType refType) {
        if (!isResolved() && refSpec.matches(refType)) {
            resolveNotify(refType);
        }
    }

    void attemptImmediateResolve(VirtualMachine vm) {
        // try to resolve immediately
        for (ReferenceType refType : vm.allClasses()) {
            if (refSpec.matches(refType)) {
                try {
                    resolve(refType);
                    status = STATUS_RESOLVED;
                    specs.notifySet(this);
                } catch(Exception exc) {
                    status = STATUS_ERROR;
                    specs.notifyError(this, exc);
                }
                return;
            }
        }
        specs.notifyDeferred(this);
    }

    public EventRequest getEventRequest() {
        return request;
    }

    /**
     * @return true if this spec has been resolved.
     */
    public boolean isResolved() {
        return status == STATUS_RESOLVED;
    }

    /**
     * @return true if this spec has not yet been resolved.
     */
    public boolean isUnresolved() {
        return status == STATUS_UNRESOLVED;
    }

    /**
     * @return true if this spec is unresolvable due to error.
     */
    public boolean isErroneous() {
        return status == STATUS_ERROR;
    }

    public String getStatusString() {
        switch (status) {
            case STATUS_RESOLVED:
                return "resolved";
            case STATUS_UNRESOLVED:
                return "deferred";
            case STATUS_ERROR:
                return "erroneous";
        }
        return "unknown";
    }

    boolean isJavaIdentifier(String s) {
        return Utils.isJavaIdentifier(s);
    }

    public String errorMessageFor(Exception e) {
        if (e instanceof IllegalArgumentException) {
            return ("Invalid command syntax");
        } else if (e instanceof RuntimeException) {
            // A runtime exception that we were not expecting
            throw (RuntimeException)e;
        } else {
            return ("Internal error; unable to set" + this);
        }
    }
}

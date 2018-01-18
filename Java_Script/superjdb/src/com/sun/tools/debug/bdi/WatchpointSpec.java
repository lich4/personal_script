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

public abstract class WatchpointSpec extends EventRequestSpec {
    final String fieldId;

    WatchpointSpec(EventRequestSpecList specs,
                   ReferenceTypeSpec refSpec, String fieldId) {
        super(specs, refSpec);
        this.fieldId = fieldId;
//        if (!isJavaIdentifier(fieldId)) {
//            throw new MalformedMemberNameException(fieldId);
//        }
    }

    @Override
    void notifySet(SpecListener listener, SpecEvent evt) {
        listener.watchpointSet(evt);
    }

    @Override
    void notifyDeferred(SpecListener listener, SpecEvent evt) {
        listener.watchpointDeferred(evt);
    }

    @Override
    void notifyResolved(SpecListener listener, SpecEvent evt) {
        listener.watchpointResolved(evt);
    }

    @Override
    void notifyDeleted(SpecListener listener, SpecEvent evt) {
        listener.watchpointDeleted(evt);
    }

    @Override
    void notifyError(SpecListener listener, SpecErrorEvent evt) {
        listener.watchpointError(evt);
    }

    @Override
    public int hashCode() {
        return refSpec.hashCode() + fieldId.hashCode() +
            getClass().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof WatchpointSpec) {
            WatchpointSpec watchpoint = (WatchpointSpec)obj;

            return fieldId.equals(watchpoint.fieldId) &&
                   refSpec.equals(watchpoint.refSpec) &&
                   getClass().equals(watchpoint.getClass());
        } else {
            return false;
        }
    }

    @Override
    public String errorMessageFor(Exception e) {
        if (e instanceof NoSuchFieldException) {
            return ("No field " + fieldId + " in " + refSpec);
        } else {
            return super.errorMessageFor(e);
        }
    }
}

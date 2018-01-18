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

public class ModificationWatchpointSpec extends WatchpointSpec {

    ModificationWatchpointSpec(EventRequestSpecList specs,
                         ReferenceTypeSpec refSpec, String fieldId) {
        super(specs, refSpec,  fieldId);
    }

    /**
     * The 'refType' is known to match.
     */
    @Override
    void resolve(ReferenceType refType) throws InvalidTypeException,
                                             NoSuchFieldException {
        if (!(refType instanceof ClassType)) {
            throw new InvalidTypeException();
        }
        Field field = refType.fieldByName(fieldId);
        if (field == null) {
            throw new NoSuchFieldException(fieldId);
        }
        setRequest(refType.virtualMachine().eventRequestManager()
                   .createModificationWatchpointRequest(field));
    }

    @Override
    public boolean equals(Object obj) {
        return (obj instanceof ModificationWatchpointSpec) &&
            super.equals(obj);
    }
}

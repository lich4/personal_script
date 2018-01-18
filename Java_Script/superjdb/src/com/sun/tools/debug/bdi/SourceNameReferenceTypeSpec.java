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

class SourceNameReferenceTypeSpec implements ReferenceTypeSpec {
    final String sourceName;
    final int linenumber;

    SourceNameReferenceTypeSpec(String sourceName, int linenumber) {
        this.sourceName = sourceName;
        this.linenumber = linenumber;
    }

    /**
     * Does the specified ReferenceType match this spec.
     */
    @Override
    public boolean matches(ReferenceType refType) {
        try {
            if (refType.sourceName().equals(sourceName)) {
                try {
                    refType.locationsOfLine(linenumber);
                    // if we don't throw an exception then it was found
                    return true;
                } catch(AbsentInformationException exc) {
                } catch(ObjectCollectedException  exc) {
                }
            }
        } catch(AbsentInformationException exc) {
            // for sourceName(), fall through
        }
        return false;
    }

    @Override
    public int hashCode() {
        return sourceName.hashCode() + linenumber;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof SourceNameReferenceTypeSpec) {
            SourceNameReferenceTypeSpec spec = (SourceNameReferenceTypeSpec)obj;

            return sourceName.equals(spec.sourceName) &&
                              (linenumber == spec.linenumber);
        } else {
            return false;
        }
    }

    @Override
    public String toString() {
        return sourceName + "@" + linenumber;
    }
}

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
import java.util.StringTokenizer;

class PatternReferenceTypeSpec implements ReferenceTypeSpec {
    final boolean isWild;
    final String classId;

    PatternReferenceTypeSpec(String classId)
//                             throws ClassNotFoundException
    {
//        checkClassName(classId);
        isWild = classId.startsWith("*.");
        if (isWild) {
            this.classId = classId.substring(1);
        } else {
            this.classId = classId;
        }
    }

    /**
     * Does the specified ReferenceType match this spec.
     */
    @Override
    public boolean matches(ReferenceType refType) {
        if (isWild) {
            return refType.name().endsWith(classId);
        } else {
            return refType.name().equals(classId);
        }
    }

    @Override
    public int hashCode() {
        return classId.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof PatternReferenceTypeSpec) {
            PatternReferenceTypeSpec spec = (PatternReferenceTypeSpec)obj;

            return classId.equals(spec.classId) && (isWild == spec.isWild);
        } else {
            return false;
        }
    }

    @SuppressWarnings("unused")
	private void checkClassName(String className) throws ClassNotFoundException {
        // Do stricter checking of class name validity on deferred
        //  because if the name is invalid, it will
        // never match a future loaded class, and we'll be silent
        // about it.
        StringTokenizer tokenizer = new StringTokenizer(className, ".");
        boolean first = true;
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken();
            // Each dot-separated piece must be a valid identifier
            // and the first token can also be "*". (Note that
            // numeric class ids are not permitted. They must
            // match a loaded class.)
            if (!Utils.isJavaIdentifier(token) && !(first && token.equals("*"))) {
                throw new ClassNotFoundException();
            }
            first = false;
        }
    }

    @Override
    public String toString() {
        return isWild? "*" + classId : classId;
    }
}

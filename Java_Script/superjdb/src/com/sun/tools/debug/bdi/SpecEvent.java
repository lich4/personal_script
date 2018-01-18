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

import java.util.EventObject;

import com.sun.jdi.request.EventRequest;

public class SpecEvent extends EventObject {

    private static final long serialVersionUID = 4820735456787276230L;
    private EventRequestSpec eventRequestSpec;

    public SpecEvent(EventRequestSpec eventRequestSpec) {
        super(eventRequestSpec.specs);
        this.eventRequestSpec = eventRequestSpec;
    }

    public EventRequestSpec getEventRequestSpec() {
        return eventRequestSpec;
    }

    public EventRequest getEventRequest() {
        return eventRequestSpec.getEventRequest();
    }
}

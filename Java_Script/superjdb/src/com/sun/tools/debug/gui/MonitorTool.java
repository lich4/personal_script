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


package com.sun.tools.debug.gui;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import com.sun.jdi.*;
import com.sun.tools.debug.bdi.*;
import com.sun.tools.example.debug.expr.ExpressionParser;
import com.sun.tools.example.debug.expr.ParseException;

public class MonitorTool extends JPanel {

    private static final long serialVersionUID = -645235951031726647L;
    private ExecutionManager runtime;
    private ContextManager context;

    private JList list;

    public MonitorTool(Environment env) {
        super(new BorderLayout());
        this.runtime = env.getExecutionManager();
        this.context = env.getContextManager();

        list = new JList(env.getMonitorListModel());
        list.setCellRenderer(new MonitorRenderer());

        JScrollPane listView = new JScrollPane(list);
        add(listView);

        // Create listener.
        MonitorToolListener listener = new MonitorToolListener();
        list.addListSelectionListener(listener);
        //### remove listeners on exit!
    }

    private class MonitorToolListener implements ListSelectionListener {
        @Override
        public void valueChanged(ListSelectionEvent e) {
            int index = list.getSelectedIndex();
            if (index != -1) {
            }
        }
    }

    private Value evaluate(String expr) throws ParseException,
                                            InvocationException,
                                            InvalidTypeException,
                                            ClassNotLoadedException,
                                            IncompatibleThreadStateException {
        ExpressionParser.GetFrame frameGetter =
            new ExpressionParser.GetFrame() {
                @Override
                public StackFrame get()
                    throws IncompatibleThreadStateException
                {
                    try {
                        return context.getCurrentFrame();
                    } catch (VMNotInterruptedException exc) {
                        throw new IncompatibleThreadStateException();
                    }
                }
            };
        return ExpressionParser.evaluate(expr, runtime.vm(), frameGetter);
    }

    private class MonitorRenderer extends DefaultListCellRenderer {

        @Override
        public Component getListCellRendererComponent(JList list,
                                                      Object value,
                                                      int index,
                                                      boolean isSelected,
                                                      boolean cellHasFocus) {

            //### We should indicate the current thread independently of the
            //### selection, e.g., with an icon, because the user may change
            //### the selection graphically without affecting the current
            //### thread.

            super.getListCellRendererComponent(list, value, index,
                                               isSelected, cellHasFocus);
            if (value == null) {
                this.setText("<unavailable>");
            } else {
                String expr = (String)value;
                try {
                    Value result = evaluate(expr);
                    this.setText(expr + " = " + result);
                } catch (ParseException exc) {
                    this.setText(expr + " ? " + exc.getMessage());
                } catch (IncompatibleThreadStateException exc) {
                    this.setText(expr + " ...");
                } catch (Exception exc) {
                    this.setText(expr + " ? " + exc);
                }
            }
            return this;
        }
    }
}

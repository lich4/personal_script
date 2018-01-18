/*
 * Copyright (c) 1998, 2011, Oracle and/or its affiliates. All rights reserved.
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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class TypeScript extends JPanel {

    private static final long serialVersionUID = -983704841363534885L;
    private JTextArea history;
    private JTextField entry;

    private JLabel promptLabel;

    private JScrollBar historyVScrollBar;
    private JScrollBar historyHScrollBar;

    private boolean echoInput = false;

    private static String newline = System.getProperty("line.separator");

    public TypeScript(String prompt) {
        this(prompt, true);
    }

    public TypeScript(String prompt, boolean echoInput) {
        this.echoInput = echoInput;

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        //setBorder(new EmptyBorder(5, 5, 5, 5));

        history = new JTextArea(0, 0);
        history.setEditable(false);
        JScrollPane scroller = new JScrollPane(history);
        historyVScrollBar = scroller.getVerticalScrollBar();
        historyHScrollBar = scroller.getHorizontalScrollBar();

        add(scroller);

        JPanel cmdLine = new JPanel();
        cmdLine.setLayout(new BoxLayout(cmdLine, BoxLayout.X_AXIS));
        //cmdLine.setBorder(new EmptyBorder(5, 5, 0, 0));

        promptLabel = new JLabel(prompt + " ");
        cmdLine.add(promptLabel);
        entry = new JTextField();
//### Swing bug workaround.
entry.setMaximumSize(new Dimension(1000, 20));
        cmdLine.add(entry);
        add(cmdLine);
    }

    /******
    public void setFont(Font f) {
        entry.setFont(f);
        history.setFont(f);
    }
    ******/

    public void setPrompt(String prompt) {
        promptLabel.setText(prompt + " ");
    }

    public void append(String text) {
        history.append(text);
        historyVScrollBar.setValue(historyVScrollBar.getMaximum());
        historyHScrollBar.setValue(historyHScrollBar.getMinimum());
    }

    public void newline() {
        history.append(newline);
        historyVScrollBar.setValue(historyVScrollBar.getMaximum());
        historyHScrollBar.setValue(historyHScrollBar.getMinimum());
    }

    public void flush() {}

    public void addActionListener(ActionListener a) {
        entry.addActionListener(a);
    }

    public void removeActionListener(ActionListener a) {
        entry.removeActionListener(a);
    }

    public String readln() {
        String text = entry.getText();
        entry.setText("");
        if (echoInput) {
            history.append(">>>");
            history.append(text);
            history.append(newline);
            historyVScrollBar.setValue(historyVScrollBar.getMaximum());
            historyHScrollBar.setValue(historyHScrollBar.getMinimum());
        }
        return text;
    }
}

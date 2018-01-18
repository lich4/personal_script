/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.ddmuilib.logcat;

import com.android.ddmlib.Log.LogLevel;
import com.android.ddmlib.logcat.LogCatFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Class to help save/restore user created filters.
 *
 * Users can create multiple filters in the logcat view. These filters could have regexes
 * in their settings. All of the user created filters are saved into a single Eclipse
 * preference. This class helps in generating the string to be saved given a list of
 * {@link LogCatFilter}'s, and also does the reverse of creating the list of filters
 * given the encoded string.
 */
public final class LogCatFilterSettingsSerializer {
    private static final char SINGLE_QUOTE = '\'';
    private static final char ESCAPE_CHAR = '\\';

    private static final String ATTR_DELIM = ", ";
    private static final String KW_DELIM = ": ";

    private static final String KW_NAME = "name";
    private static final String KW_TAG = "tag";
    private static final String KW_TEXT = "text";
    private static final String KW_PID = "pid";
    private static final String KW_APP = "app";
    private static final String KW_LOGLEVEL = "level";

    /**
     * Encode the settings from a list of {@link LogCatFilter}'s into a string for saving to
     * the preference store. See
     * {@link LogCatFilterSettingsSerializer#decodeFromPreferenceString(String)} for the
     * reverse operation.
     * @param filters list of filters to save.
     * @param filterData mapping from filter to per filter UI data
     * @return an encoded string that can be saved in Eclipse preference store. The encoded string
     * is of a list of key:'value' pairs.
     */
    public String encodeToPreferenceString(List<LogCatFilter> filters,
            Map<LogCatFilter, LogCatFilterData> filterData) {
        StringBuffer sb = new StringBuffer();

        for (LogCatFilter f : filters) {
            LogCatFilterData fd = filterData.get(f);
            if (fd != null && fd.isTransient()) {
                // do not persist transient filters
                continue;
            }

            sb.append(KW_NAME); sb.append(KW_DELIM); sb.append(quoteString(f.getName()));
                                                                        sb.append(ATTR_DELIM);
            sb.append(KW_TAG);  sb.append(KW_DELIM); sb.append(quoteString(f.getTag()));
                                                                        sb.append(ATTR_DELIM);
            sb.append(KW_TEXT); sb.append(KW_DELIM); sb.append(quoteString(f.getText()));
                                                                        sb.append(ATTR_DELIM);
            sb.append(KW_PID);  sb.append(KW_DELIM); sb.append(quoteString(f.getPid()));
                                                                        sb.append(ATTR_DELIM);
            sb.append(KW_APP);  sb.append(KW_DELIM); sb.append(quoteString(f.getAppName()));
                                                                        sb.append(ATTR_DELIM);
            sb.append(KW_LOGLEVEL); sb.append(KW_DELIM);
                                       sb.append(quoteString(f.getLogLevel().getStringValue()));
                                       sb.append(ATTR_DELIM);
        }
        return sb.toString();
    }

    /**
     * Decode an encoded string representing the settings of a list of logcat
     * filters into a list of {@link LogCatFilter}'s.
     * @param pref encoded preference string
     * @return a list of {@link LogCatFilter}
     */
    public List<LogCatFilter> decodeFromPreferenceString(String pref) {
        List<LogCatFilter> fs = new ArrayList<LogCatFilter>();

        /* first split the string into a list of key, value pairs */
        List<String> kv = getKeyValues(pref);
        if (kv.size() == 0) {
            return fs;
        }

        /* construct filter settings from the key value pairs */
        int index = 0;
        while (index < kv.size()) {
            String name = "";
            String tag = "";
            String pid = "";
            String app = "";
            String text = "";
            LogLevel level = LogLevel.VERBOSE;

            assert kv.get(index).equals(KW_NAME);
            name = kv.get(index + 1);

            index += 2;
            while (index < kv.size() && !kv.get(index).equals(KW_NAME)) {
                String key = kv.get(index);
                String value = kv.get(index + 1);
                index += 2;

                if (key.equals(KW_TAG)) {
                    tag = value;
                } else if (key.equals(KW_TEXT)) {
                    text = value;
                } else if (key.equals(KW_PID)) {
                    pid = value;
                } else if (key.equals(KW_APP)) {
                    app = value;
                } else if (key.equals(KW_LOGLEVEL)) {
                    level = LogLevel.getByString(value);
                }
            }

            fs.add(new LogCatFilter(name, tag, text, pid, app, level));
        }

        return fs;
    }

    private List<String> getKeyValues(String pref) {
        List<String> kv = new ArrayList<String>();
        int index = 0;
        while (index < pref.length()) {
            String kw = getKeyword(pref.substring(index));
            if (kw == null) {
                break;
            }
            index += kw.length() + KW_DELIM.length();

            String value = getNextString(pref.substring(index));
            index += value.length() + ATTR_DELIM.length();

            value = unquoteString(value);

            kv.add(kw);
            kv.add(value);
        }

        return kv;
    }

    /**
     * Enclose a string in quotes, escaping all the quotes within the string.
     */
    private String quoteString(String s) {
        return SINGLE_QUOTE + s.replace(Character.toString(SINGLE_QUOTE), "\\'")
                + SINGLE_QUOTE;
    }

    /**
     * Recover original string from its escaped version created using
     * {@link LogCatFilterSettingsSerializer#quoteString(String)}.
     */
    private String unquoteString(String s) {
        s = s.substring(1, s.length() - 1); /* remove start and end QUOTES */
        return s.replace("\\'", Character.toString(SINGLE_QUOTE));
    }

    private String getKeyword(String pref) {
        int kwlen = pref.indexOf(KW_DELIM);
        if (kwlen == -1) {
            return null;
        }

        return pref.substring(0, kwlen);
    }

    /**
     * Get the next quoted string from the input stream of characters.
     */
    private String getNextString(String s) {
        assert s.charAt(0) == SINGLE_QUOTE;

        StringBuffer sb = new StringBuffer();

        int index = 0;
        while (index < s.length()) {
            sb.append(s.charAt(index));

            if (index > 0
                    && s.charAt(index) == SINGLE_QUOTE          // current char is a single quote
                    && s.charAt(index - 1) != ESCAPE_CHAR) {    // prev char wasn't a backslash
                /* break if an unescaped SINGLE QUOTE (end of string) is seen */
                break;
            }

            index++;
        }

        return sb.toString();
    }
}

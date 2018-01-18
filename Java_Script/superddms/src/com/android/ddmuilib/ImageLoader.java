/*
 * Copyright (C) 2007 The Android Open Source Project
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

package com.android.ddmuilib;

import com.android.ddmlib.Log;

import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.swt.SWT;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.GC;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.widgets.Display;

import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;

/**
 * Class to load images stored in a jar file.
 * All images are loaded from /images/<var>filename</var>
 *
 * Because Java requires to know the jar file in which to load the image from, a class is required
 * when getting the instance. Instances are cached and associated to the class passed to
 * {@link #getLoader(Class)}.
 *
 * {@link #getDdmUiLibLoader()} use {@link ImageLoader#getClass()} as the class. This is to be used
 * to load images from ddmuilib.
 *
 * Loaded images are stored so that 2 calls with the same filename will return the same object.
 * This also means that {@link Image} object returned by the loader should never be disposed.
 *
 */
public class ImageLoader {

    private static final String PATH = "/images/"; //$NON-NLS-1$

    private final HashMap<String, Image> mLoadedImages = new HashMap<String, Image>();
    private static final HashMap<Class<?>, ImageLoader> mInstances =
            new HashMap<Class<?>, ImageLoader>();
    private final Class<?> mClass;

    /**
     * Private constructor, creating an instance associated with a class.
     * The class is used to identify which jar file the images are loaded from.
     */
    private ImageLoader(Class<?> theClass) {
        if (theClass == null) {
            theClass = ImageLoader.class;
        }
        mClass = theClass;
    }

    /**
     * Returns the {@link ImageLoader} instance to load images from ddmuilib.jar
     */
    public static ImageLoader getDdmUiLibLoader() {
        return getLoader(null);
    }

    /**
     * Returns an {@link ImageLoader} to load images based on a given class.
     *
     * The loader will load images from the jar from which the class was loaded. using
     * {@link Class#getResource(String)} and {@link Class#getResourceAsStream(String)}.
     *
     * Since all images are loaded using the path /images/<var>filename</var>, any class from the
     * jar will work. However since the loader is cached and reused when the query provides the same
     * class instance, and since the loader will also cache the loaded images, it is recommended
     * to always use the same class for a given Jar file.
     *
     */
    public static ImageLoader getLoader(Class<?> theClass) {
        ImageLoader instance = mInstances.get(theClass);
        if (instance == null) {
            instance = new ImageLoader(theClass);
            mInstances.put(theClass, instance);
        }

        return instance;
    }

    /**
     * Disposes all images for all instances.
     * This should only be called when the program exits.
     */
    public static void dispose() {
        for (ImageLoader loader : mInstances.values()) {
            loader.doDispose();
        }
    }

    private synchronized void doDispose() {
        for (Image image : mLoadedImages.values()) {
            image.dispose();
        }

        mLoadedImages.clear();
    }

    /**
     * Returns an {@link ImageDescriptor} for a given filename.
     *
     * This searches for an image located at /images/<var>filename</var>.
     *
     * @param filename the filename of the image to load.
     */
    public ImageDescriptor loadDescriptor(String filename) {
        URL url = mClass.getResource(PATH + filename);
        // TODO cache in a map
        return ImageDescriptor.createFromURL(url);
    }

    /**
     * Returns an {@link Image} for a given filename.
     *
     * This searches for an image located at /images/<var>filename</var>.
     *
     * @param filename the filename of the image to load.
     * @param display the Display object
     */
    public synchronized Image loadImage(String filename, Display display) {
        Image img = mLoadedImages.get(filename);
        if (img == null) {
            String tmp = PATH + filename;
            InputStream imageStream = mClass.getResourceAsStream(tmp);

            if (imageStream != null) {
                img = new Image(display, imageStream);
                mLoadedImages.put(filename, img);
            }

            if (img == null) {
                throw new RuntimeException("Failed to load " + tmp);
            }
        }

        return img;
    }

    /**
     * Loads an image from a resource. This method used a class to locate the
     * resources, and then load the filename from /images inside the resources.<br>
     * Extra parameters allows for creation of a replacement image of the
     * loading failed.
     *
     * @param display the Display object
     * @param fileName the file name
     * @param width optional width to create replacement Image. If -1, null be
     *            be returned if the loading fails.
     * @param height optional height to create replacement Image. If -1, null be
     *            be returned if the loading fails.
     * @param phColor optional color to create replacement Image. If null, Blue
     *            color will be used.
     * @return a new Image or null if the loading failed and the optional
     *         replacement size was -1
     */
    public Image loadImage(Display display, String fileName, int width, int height,
            Color phColor) {

        Image img = loadImage(fileName, display);

        if (img == null) {
            Log.w("ddms", "Couldn't load " + fileName);
            // if we had the extra parameter to create replacement image then we
            // create and return it.
            if (width != -1 && height != -1) {
                return createPlaceHolderArt(display, width, height,
                        phColor != null ? phColor : display
                                .getSystemColor(SWT.COLOR_BLUE));
            }

            // otherwise, just return null
            return null;
        }

        return img;
    }

    /**
     * Create place-holder art with the specified color.
     */
    public static Image createPlaceHolderArt(Display display, int width,
            int height, Color color) {
        Image img = new Image(display, width, height);
        GC gc = new GC(img);
        gc.setForeground(color);
        gc.drawLine(0, 0, width, height);
        gc.drawLine(0, height - 1, width, -1);
        gc.dispose();
        return img;
    }
}

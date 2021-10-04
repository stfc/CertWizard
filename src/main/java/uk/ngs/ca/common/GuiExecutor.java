/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.common;

import javax.swing.*;

/**
 * Singleton that executes the given <tt>Runnable</tt> in the AWT event
 * dispatching thread.
 *
 * @author David Meredith
 */
public class GuiExecutor {

    // singleton's have a private constructor and static factory 
    private static final GuiExecutor instance = new GuiExecutor();

    private GuiExecutor() {
    }

    public static GuiExecutor instance() {
        return instance;
    }

    /**
     * Execute the given <tt>Runnable</tt> in the AWT event dispatching thread.
     * <p>
     * If the calling thread is not itself in the AWT event dispatch thread,
     * then the Runnable is run asynchronously via {@link SwingUtilities#invokeLater(java.lang.Runnable)
     * }.
     * <p>
     * If the calling thread is itself in the AWT event dispatch thread, then
     * the Runnable is run immediately using {@link Runnable#run()}.
     *
     * @param r Runnable instance
     */
    public void execute(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }
}

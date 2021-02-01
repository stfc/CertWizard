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

import java.util.Observable;
import java.util.concurrent.*;

/**
 * Generic class for running background tasks that provide task completion and
 * progress call backs. Subclasses need only implement <tt>compute()</tt>
 * which is called in the background thread. You MAY optionally override
 * <tt>onCompletion()</tt> and <tt>onProgress()</tt> which are invoked in the
 * AWT Event Dispatch Thread. In a subclass, you can call <tt>setProgress</tt>
 * method from <tt>compute</tt>
 * method to indicate progress numerically.
 * <p>
 * Modified from JAVA Concurrency in Practice by Brian Goetz. This class
 * provides very similar functionality to <tt>SwingWorker</tt> introduced in
 * JKD1.6.
 *
 * @author David Meredith
 */
public abstract class BackgroundTask<V> extends Observable implements Runnable, Future<V> {

    // manage our own instance of Computation FutureTask 
    private final FutureTask<V> computation = new Computation();

    /**
     * current state.
     */
    protected volatile StateValue state = StateValue.PENDING;

    ;

    
    /**
     * Values for the {@code state} bound property.
     */
    public enum StateValue {

        /**
         * Initial state.
         */
        PENDING,
        /**
         * is {@code STARTED} before invoking {@code doInBackground}.
         */
        STARTED,
        /**
         * is {@code DONE} after {@code doInBackground} method is finished.
         */
        DONE
    }

    /**
     * Since Computation extends FutureTask, we can override <tt>done</tt> and
     * run our <tt>onCompletion</tt> and <tt>onProgress</tt> methods in the
     * Event Dispatch (GUI) thread.
     */
    private class Computation extends FutureTask<V> {

        public Computation() {
            // Computation is a <tt>FutureTask</tt> that will, 
            // upon running, execute the given <tt>Callable</tt> instance.
            super(new Callable<V>() {
                public V call() throws Exception {
                    state = StateValue.STARTED;
                    return BackgroundTask.this.doInBackground();
                }
            });
        }

        /**
         * Invoked when this task transitions to state
         * <tt>isDone</tt> (whether normally or via cancellation). The default
         * implementation does nothing. Subclasses may override this method to
         * invoke completion callbacks or perform bookkeeping. Note that you can
         * query status inside the implementation of this method to determine
         * whether this task has been cancelled.
         */
        @Override
        protected final void done() {
            state = StateValue.DONE;
            // call onCompletion() in the GUI Event Dispatch Thread
            GuiExecutor.instance().execute(new Runnable() {

                public void run() {
                    V value = null;
                    Throwable thrown = null;
                    boolean cancelled = false;
                    try {
                        value = get();
                    } catch (ExecutionException ex) {
                        thrown = ex.getCause();
                    } catch (CancellationException ex) {
                        cancelled = true;
                    } catch (InterruptedException consumed) {
                        // do nothing 
                    } finally {
                        // Call our handler (designed to be overridden) 
                        onCompletion(value, thrown, cancelled);
                    }
                }
            });
        }
    } // end of Computation class 

    /**
     * Returns the {@code SwingWorker} state bound property.
     *
     * @return the current state
     */
    public final StateValue getState() {
        return this.state;
    }

    /**
     * Call this method from within your overridden <tt>compute</tt> method to
     * indicate progress numerically.
     *
     * @param current
     * @param max
     */
    protected void setProgress(final int current, final int max) {
        // call onCompletion() in the GUI Event Dispatch Thread
        GuiExecutor.instance().execute(new Runnable() {
            public void run() {
                onProgress(current, max);
            }
        });
    }

    /**
     * Override this method to implement your long running task. This method is
     * called in the background thread.
     *
     * @return The result type returned by this FutureTask's <tt>get</tt> method
     * @throws Exception
     */
    protected abstract V doInBackground() throws Exception;

    /**
     * Optional callback method that is called in the GUI event dispatch thread
     * after the compute task finishes. Override this method to handle the on
     * completion event.
     *
     * @param result
     * @param exception
     * @param cancelled
     */
    protected void onCompletion(V result, Throwable exception, boolean cancelled) {
    }

    /**
     * Optional callback method that is called called in the GUI event dispatch
     * thread. Override this method to handle the progress callbacks (note, for
     * this overridden method to be called, the overridden compute task MUST
     * invoke {@link #setProgress(int, int)}).
     *
     * @param current
     * @param max
     */
    protected void onProgress(int current, int max) {
    }

    // Other Future methods forwarded to computation 
    public void run() {
        computation.run();
    }

    public boolean cancel(boolean mayInterruptIfRunning) {
        return computation.cancel(mayInterruptIfRunning);
    }

    public boolean isCancelled() {
        return computation.isCancelled();
    }

    public boolean isDone() {
        return computation.isDone();
    }

    public V get() throws InterruptedException, ExecutionException {
        return computation.get();
    }

    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        return computation.get(timeout, unit);
    }

} // end of BackgroundTask 

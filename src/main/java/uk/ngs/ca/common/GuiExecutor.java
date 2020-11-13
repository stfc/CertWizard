package uk.ngs.ca.common;

import javax.swing.SwingUtilities;

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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.awt.Dimension;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import javax.swing.JPanel;
import org.globus.cog.gui.setup.components.DoActionsComponent;
import org.globus.common.CoGProperties;

/**
 *
 * @author xw75
 */
public class DoActionsPanel extends JPanel {

    private DoActionsComponent doActions ;

    public DoActionsPanel(JPanel parent) {
        super();

         doActions = new DoActionsComponent(CoGProperties.getDefault());

        doActions.setPreferredSize(new Dimension(parent.getWidth(), parent.getHeight())); //500, 500
        doActions.setVisible(true);
        this.add(doActions);

        parent.addComponentListener(new ComponentListener() {

            public void componentResized(ComponentEvent e) {
                doActions.setPreferredSize(e.getComponent().getWidth(), e.getComponent().getHeight());
                revalidate();
            }

            public void componentMoved(ComponentEvent e) {
                //throw new UnsupportedOperationException("Not supported yet.");
            }

            public void componentShown(ComponentEvent e) {
                //throw new UnsupportedOperationException("Not supported yet.");
            }

            public void componentHidden(ComponentEvent e) {
                //throw new UnsupportedOperationException("Not supported yet.");
            }
        });
    }

    /**
     * Calls update on the DoActionsComponent member var. 
     */
    public void update(){
        this.doActions.enter();
    }
}

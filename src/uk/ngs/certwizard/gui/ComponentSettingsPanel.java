/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.awt.Dimension;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import javax.swing.JPanel;
import org.globus.cog.gui.setup.panels.ListPanel;
import org.globus.cog.gui.setup.panels.LogoPanel;
import org.globus.cog.gui.setup.panels.NavPanel;
import org.globus.cog.gui.setup.panels.TitlePanel;
import org.globus.cog.gui.util.GridContainer;
import org.globus.cog.gui.util.SimpleGridLayout;


/**
 *
 * @author xw75
 */
public class ComponentSettingsPanel extends JPanel {

    private ComponentPanel2 componentPanel;

    public ComponentSettingsPanel(final JPanel parent) {
        super();

        final GridContainer contentPane = new GridContainer(1, 2);
        contentPane.setPreferredSize(parent.getWidth(), parent.getHeight());

        GridContainer leftPanel = new GridContainer(2, 1);
        leftPanel.setPreferredSize(new Dimension(164, SimpleGridLayout.Expand));

        LogoPanel logoPanel = new LogoPanel();
        //140,60
        logoPanel.setPreferredSize(new Dimension(160, 40));
        ListPanel listPanel = new ListPanel();
        listPanel.setPreferredSize(new Dimension(160, SimpleGridLayout.Expand));
        //AboutPanel aboutPanel = new AboutPanel();
        //aboutPanel.setPreferredSize(new Dimension(160, 50));

        leftPanel.add(logoPanel);
        leftPanel.add(listPanel);
        //leftPanel.add(aboutPanel);

        contentPane.add(leftPanel);

        GridContainer centerPanel = new GridContainer(3, 1);
        centerPanel.setPreferredSize(
                new Dimension(SimpleGridLayout.Expand, SimpleGridLayout.Expand));

        TitlePanel titlePanel = new TitlePanel();
        titlePanel.setPreferredSize(new Dimension(SimpleGridLayout.Expand, 40));
        NavPanel navPanel = new NavPanel();
        navPanel.setPreferredSize(new Dimension(SimpleGridLayout.Expand, 50));
        //navPanel.addNavEventListener(this);
        //ComponentPanel2 componentPanel =
        componentPanel =
                new ComponentPanel2(titlePanel, listPanel, navPanel);
        componentPanel.setPreferredSize(
                new Dimension(SimpleGridLayout.Expand, SimpleGridLayout.Expand));

        centerPanel.add(titlePanel);
        centerPanel.add(componentPanel);
        centerPanel.add(navPanel);

        contentPane.add(centerPanel);

        this.add(contentPane);

        parent.addComponentListener(new ComponentListener() {

            public void componentResized(ComponentEvent e) {
                contentPane.setPreferredSize(e.getComponent().getWidth(), e.getComponent().getHeight());
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



    
    public void updateCertificateComponent(){
        //this.componentPanel.componentStatusChanged(null);
        //this.componentPanel.updateUserCertificateComponent();
        this.componentPanel.updateUserCertificateComponent();
    }

}

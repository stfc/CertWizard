/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.certwizard.gui;

import java.util.TimerTask;

/**
 *
 * @author xw75
 */
public class RefreshOnLine extends TimerTask {

    MainWindowPanel mainWindowPanel;
    public RefreshOnLine( MainWindowPanel mainWindowPanel ){
        this.mainWindowPanel = mainWindowPanel;
    }

    public void run(){
        mainWindowPanel.refreshOnLine();
    }


}

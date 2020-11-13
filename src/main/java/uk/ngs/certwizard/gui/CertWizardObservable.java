/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.util.Observable;
import uk.ngs.ca.certificate.management.CertificateCSRInfo;

/**
 *
 * @author xw75
 */
public class CertWizardObservable extends Observable {

    public CertWizardObservable() {

    }

    public void change(CertificateCSRInfo info) {
        setChanged();
        notifyObservers(info);
    }

}

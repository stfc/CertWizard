/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.io.File;
import javax.swing.filechooser.FileFilter;

/**
 *
 * @author xw75
 */
public class ExportFilter extends FileFilter {

    @Override
    public boolean accept(File f) {
        if (f.isDirectory()) {
            return true;
        } else {
            return f.getName().endsWith(".pfx");
        }
    }

    @Override
    public String getDescription() {
        return "Certificate (.pfx)";
    }
}

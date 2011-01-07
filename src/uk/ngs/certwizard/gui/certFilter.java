package uk.ngs.certwizard.gui;

import java.io.File;
import javax.swing.filechooser.FileFilter;

public class certFilter extends FileFilter {

    @Override
    public boolean accept(File f) {
        if (f.isDirectory()) {
            return true;
        } else {
            return f.getName().endsWith(".pfx") || f.getName().endsWith(".p12");
        }
    }

    @Override
    public String getDescription() {
        return "Certificate (.pfx, .p12)";
    }
}

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package utils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 *
 * @author David Meredith
 */
public class TestUtil {
    
    /**
     * Read the given file contents and return as a string. 
     * @param file File object to read. 
     * @return File content as string. 
     * @throws java.io.IOException 
     */
    public static String readFileAsString(File file) throws java.io.IOException {
        return readFileAsString(file.getAbsolutePath()); 
    }
    
    /**
     * Read the given file contents and return as a string. 
     * @param filePath Full path of file to read. 
     * @return File content as string. 
     * @throws java.io.IOException 
     */
    public static String readFileAsString(String filePath) throws java.io.IOException {
        byte[] buffer = new byte[(int) new File(filePath).length()];
        BufferedInputStream f = null;
        try {
            f = new BufferedInputStream(new FileInputStream(filePath));
            f.read(buffer);
        } finally {
            if (f != null) {
                try {
                    f.close();
                } catch (IOException ignored) {
                }
            }
        }
        return new String(buffer);
    }
    
}

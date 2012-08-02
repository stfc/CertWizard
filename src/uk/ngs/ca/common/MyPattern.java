/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author xw75
 */
public class MyPattern {

    private String errorMessage = null;
    private String CN = null;

    public String getErrorMessage() {
        return this.errorMessage;
    }

    public String getCN() {
        return this.CN;
    }

    public boolean isValidCN(String myCN) {
        String _myCN = _getCN(myCN);
        String[] _myCNs = _myCN.split("\\s");
        int lengthCN = 0;

        for (int i = 0; i < _myCNs.length; i++) {
            if (_myCNs[i].length() >= 2) {
                lengthCN = lengthCN + 1;
            }
        }
        if (lengthCN >= 2) {
            return true;
        } else {
            errorMessage = "The information entered in Name field is not valid. You must provide at least one given name and a surname separated by space";
            return false;
        }
    }

    private String _getCN(String myCN) {
        String cn = "";
        Pattern p = Pattern.compile("[^-()A-Za-z0-9\\s]");
        char[] mychar = myCN.toCharArray();
        boolean isSpace = false;
        for (int i = 0; i < mychar.length; i++) {
            char[] myC = new char[1];
            myC[ 0] = mychar[i];
            String myS = new String(myC);
            Matcher m = p.matcher(myS);
            boolean myB = m.matches();

            if (myB) {
                myS = "";
            } else {
                if (myS.equals(" ")) {
                    if (isSpace) {
                        myS = "";
                    } else {
                        isSpace = true;
                    }
                } else {
                    isSpace = false;
                }
            }
            cn = cn + myS;

        }
        cn = cn.toLowerCase().trim();
        this.CN = cn;
        return cn;
    }
/*
    public static void main(String[] arge) {
        MyPattern p = new MyPattern();
//        String _cn = "  hHHHello    this is %  a  b  W_o @!\"£$  %^&*()_+:@~;'#,./<>?rld   ";
//        String _cn = "%$%^& %^^%$^ tt t ";
        String _cn = "erer";
        boolean b = p.isValidCN(_cn);
        if (b) {
            String cn = p.getCN();
            System.out.println("cn = " + cn + ".");
        } else {
            String err = p.getErrorMessage();
            System.out.println("error = " + err);
        }

        String sss = "-35";
        Integer i = new Integer( sss );
        System.out.println("int = " + i.intValue());
//        String s = MyPattern.getCN("  hHHHello this is%  a   W_o @!\"£$  %^&*()_+:@~;'#,./<>?rld   ");
//        System.out.println("s = " + s + ".");
    }
*/
}

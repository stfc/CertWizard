
import java.io.FileWriter;
import java.io.IOException;
import java.util.Observable;
import java.util.Observer;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * NewJPanelTest.java
 *
 * Created on 13-Dec-2010, 12:37:42
 */

/**
 *
 * @author xw75
 */
public class NewJPanelTest extends javax.swing.JPanel implements Observer {

    /** Creates new form NewJPanelTest */
    public NewJPanelTest() {
        initComponents();
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();

        jLabel1.setText("jLabel1");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(63, 63, 63)
                .addComponent(jLabel1)
                .addContainerGap(303, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(60, 60, 60)
                .addComponent(jLabel1)
                .addContainerGap(226, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    // End of variables declaration//GEN-END:variables

    public static void main( String[] args ){
        NewJPanelTest p = new NewJPanelTest();
        String s = "abcdefg 1234567";
        System.out.println("s = " + s );
        s = s.replaceAll("abc", "ABCWWW");
        System.out.println("s = " + s);

        try {
      FileWriter out = new FileWriter("lpt1");
      out.write("Hello world");
      out.write(0x0D); // CR
      out.close();
      }
    catch (IOException e) {
      e.printStackTrace();
      }

    }

    public void update(Observable o, Object arg) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}

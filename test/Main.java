/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author xw75
 */
import java.awt.*;
import java.awt.event.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.swing.*;
 
class Main extends JFrame
{
  CardLayout cl = new CardLayout();
  JPanel cardLayoutPanel = new JPanel(cl);

//  cardLayoutPanel.setLayout(cl);

  public Main(String title)
  {
    super(title);
//    cardLayoutPanel.add("A",new ClassA().panel);
//    cardLayoutPanel.add("B",new ClassB().panel);
cardLayoutPanel.add(new ClassA().panel, "A");
cardLayoutPanel.add(new ClassB().panel, "B");
    add(cardLayoutPanel);
    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    pack();
    setResizable(false);
    setVisible(true);

    coding();
  }

  private void coding(){
      String c = "C=UK,O=eScienceDev,OU=CLRC,L=DL,CN=xiao wang";

      byte[] b = org.bouncycastle.util.encoders.Base64.encode(c.getBytes());
String sb = new String( b );
//      String sb = b.toString();
      byte[] _b = org.bouncycastle.util.encoders.Base64.decode(sb);
//      byte[] _b = org.bouncycastle.util.encoders.Base64.decode(b);
      String _c = new String( _b );
      System.out.println("c = " + c );
      System.out.println("_c = " + _c );
      System.out.println("sb = " + sb);
System.out.println("string b = " + b.toString());
System.out.println("string _b = " + _b.toString());
java.util.Date d = new java.util.Date();
System.out.println(" date time = " + d.getTime() );


        DateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        Date date = new Date();
        String s = dateFormat.format(date);
System.out.println("date string = " + s);


  }

  class ClassA
  {
    JPanel panel;
    public ClassA()
    {
      panel = new JPanel();
      panel.setPreferredSize(new Dimension(300,300));
      panel.setBorder(BorderFactory.createTitledBorder("Class A"));
      JButton button = new JButton("Go to B");
      button.addActionListener(new ActionListener(){
        public void actionPerformed(ActionEvent e){
          cl.show(cardLayoutPanel,"B");
        }
      });
      panel.add(button);
      //add(panel);
    }
  }
  class ClassB
  {
    JPanel panel;
    public ClassB(){
      panel = new JPanel();
      panel.setPreferredSize(new Dimension(300,300));
      panel.setBorder(BorderFactory.createTitledBorder("Class B"));
      JButton button = new JButton("Go back to A");
      button.addActionListener(new ActionListener(){
        public void actionPerformed(ActionEvent e){
          cl.show(cardLayoutPanel,"A");
        }
      });
      panel.add(button);
      //add(panel);
    }
  }
  public static void main(String[] args)
  {
    new Main("Main");
  }
}

import java.awt.BorderLayout;
import java.awt.event.KeyEvent;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class MainClass {
  public static void main(String args[]) throws Exception {
    JFrame frame = new JFrame();
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

    JTabbedPane tabbedPane = new JTabbedPane();
    tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
    String titles[] = { "A", "B", "C", "D", "E", "F" };
    int mnemonic[] = { KeyEvent.VK_A, KeyEvent.VK_B, KeyEvent.VK_C, KeyEvent.VK_D, KeyEvent.VK_E,
        KeyEvent.VK_F };
    for (int i = 0, n = titles.length; i < n; i++) {
      add(tabbedPane, titles[i], mnemonic[i]);
    }

    ChangeListener changeListener = new ChangeListener() {
      public void stateChanged(ChangeEvent changeEvent) {
        JTabbedPane sourceTabbedPane = (JTabbedPane) changeEvent.getSource();
        int index = sourceTabbedPane.getSelectedIndex();
        System.out.println("Tab changed to: " + sourceTabbedPane.getTitleAt(index));
      }
    };
    tabbedPane.addChangeListener(changeListener);

    frame.add(tabbedPane, BorderLayout.CENTER);
    frame.setSize(400, 150);
    frame.setVisible(true);

  }

  static void add(JTabbedPane tabbedPane, String label, int mnemonic) {
    int count = tabbedPane.getTabCount();
    JButton button = new JButton(label);
    tabbedPane.addTab(label, button);
    tabbedPane.setMnemonicAt(count, mnemonic);
  }

}
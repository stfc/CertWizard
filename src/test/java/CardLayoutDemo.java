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
import javax.swing.*;

public class CardLayoutDemo
{
  final static String GAME_PANEL = "Game Panel";
  final static String HIGH_SCORES_PANEL = "High Scores Panel";

  JPanel cards;

  public void addComponentToPane(Container pane)
  {
    PanelA cardA = new PanelA();
    cardA.addButtonListener(new ButtonListener(HIGH_SCORES_PANEL));

    PanelB cardB = new PanelB();
    cardB.addButtonListener(new ButtonListener(GAME_PANEL));

    cards = new JPanel(new CardLayout());
    cards.add(cardA, GAME_PANEL);
    cards.add(cardB, HIGH_SCORES_PANEL);

    pane.add(cards, BorderLayout.CENTER);
  }

  private static void createAndShowGUI()
  {
    JFrame frame = new JFrame("CardLayoutDemo");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

    CardLayoutDemo demo = new CardLayoutDemo();
    demo.addComponentToPane(frame.getContentPane());

    frame.setSize(400, 300);
    frame.setVisible(true);
  }

  public static void main(String[] args)
  {
    javax.swing.SwingUtilities.invokeLater(new Runnable()
    {
       public void run()
       {
          createAndShowGUI();
       }
    });
  }

  class PanelA extends JPanel
  {
    JLabel gameInfo = new JLabel("Here's how you play the game, etc.");
    JButton btnSubmit = new JButton("Submit");

    public PanelA()
    {
      setLayout(new BorderLayout());
      setBorder(BorderFactory.createTitledBorder("Panel A"));
      add(gameInfo, BorderLayout.CENTER);
      add(btnSubmit, BorderLayout.SOUTH);
    }

    public void addButtonListener(ActionListener l)
    {
      btnSubmit.addActionListener(l);
    }
  }

  class PanelB extends JPanel
  {
    JLabel scoresInfo = new JLabel("Here are your high scores: 100, 100, 95");
    JButton btnBack = new JButton("Back To Game");

    public PanelB()
    {
      setLayout(new BorderLayout());
      setBorder(BorderFactory.createTitledBorder("Panel B"));
      add(scoresInfo, BorderLayout.CENTER);
      add(btnBack, BorderLayout.SOUTH);
    }

    public void addButtonListener(ActionListener l)
    {
      btnBack.addActionListener(l);
    }
  }

  class ButtonListener implements ActionListener
  {
    String command;

    public ButtonListener(String command)
    {
      this.command = command;
    }

    public void actionPerformed(ActionEvent evt)
    {
      CardLayout cl = (CardLayout)(cards.getLayout());
      cl.show(cards, command);
    }
  }
}

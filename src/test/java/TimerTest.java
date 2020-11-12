/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
import java.util.Timer;
import java.util.TimerTask;
/**
 *
 * @author xw75
 */
public class TimerTest {

    Timer timer;

    public TimerTest( int seconds ){
        timer = new Timer();
        timer.schedule(new Task(), seconds*1000, seconds*1000);
    }

    class Task extends TimerTask
    {
        public void run(){
            System.out.println("OK, it's time to do something!");
//            timer.cancel();
        }
    }

    public static void main( String[] args ){
        System.out.println("schedule something to do in 5 seconds");
        new TimerTest( 2 );
        System.out.println( "Waiting...");
    }
}

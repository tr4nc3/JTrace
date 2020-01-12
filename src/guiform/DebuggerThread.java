/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package guiform;


/**
 *
 * @author Trance
 */
public class DebuggerThread extends Thread {
    private static JavaDebugger jd = null;
    boolean keepRunning ;
    
    public DebuggerThread(JavaDebugger jdInstance) {
        if (jd == null ) {
            jd = jdInstance;
            keepRunning = true;
        }
    }
    @Override
    public void run() {
        while (keepRunning) {
            jd.run();
           //start();
        }
        //
    }
    public void setStopFlag() {
        keepRunning = false;
        jd.disconnectFromVM();
    }
    public void setStartFlag() {
        keepRunning = true;
    }
}

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package guiform;

import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;

/**
 *
 * @author Trance
 */
public class MyPopupMenuListener implements PopupMenuListener {
    public void popupMenuCanceled(PopupMenuEvent popupMenuEvent) {
        System.out.println("Canceled");
    }

    public void popupMenuWillBecomeInvisible(PopupMenuEvent popupMenuEvent) {
        System.out.println("Becoming Invisible");
    }

    public void popupMenuWillBecomeVisible(PopupMenuEvent popupMenuEvent) {
        System.out.println("Becoming Visible");
    }
}

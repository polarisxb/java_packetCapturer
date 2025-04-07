// Main.java
package com.network;
import com.network.view.MainFrame;

import javax.swing.*;

// com.network.Main
public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            // 直接启动主界面
            MainFrame mainFrame = new MainFrame();
            mainFrame.setVisible(true);
        });
    }
}
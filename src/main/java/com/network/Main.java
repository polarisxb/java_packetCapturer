// Main.java
package com.network;

import com.network.view.MainFrame;
import javax.swing.*;

/**
 * 应用程序主入口类
 * 负责安全启动Swing图形界面应用程序
 */
public class Main {
    /**
     * 应用程序启动入口
     * @param args 命令行参数（本程序未使用）
     *
     * @implSpec 使用Swing事件调度线程(EDT)启动GUI界面，符合Swing线程安全规范
     */
    public static void main(String[] args) {
        // 在事件调度线程中初始化GUI（Swing线程安全要求）
        SwingUtilities.invokeLater(() -> {
            try {
                // 创建并显示主界面
                MainFrame mainFrame = new MainFrame();
                mainFrame.setVisible(true);
            } catch (Exception e) {
                // 处理未捕获的启动异常
                JOptionPane.showMessageDialog(
                        null,
                        "程序启动失败: " + e.getMessage(),
                        "致命错误",
                        JOptionPane.ERROR_MESSAGE
                );
                System.exit(1);
            }
        });
    }
}
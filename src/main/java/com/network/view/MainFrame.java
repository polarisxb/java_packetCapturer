package com.network.view;

import com.network.controller.NetworkController;
import com.network.model.NetworkInterfaceWrapper;
import com.network.service.NetworkAnalyzer;
import com.network.service.PacketCaptureService;
import org.jfree.data.category.DefaultCategoryDataset;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

public class MainFrame extends JFrame implements PacketTableModel.DataUpdateListener{
    //核心组件
    private final NetworkController controller = new NetworkController();
    private final PacketTableModel tableModel = new PacketTableModel();
    private JComboBox<NetworkInterfaceWrapper> deviceCombo;
    private PacketCaptureService captureService; // 添加服务引用
    private JLabel statusLabel = new JLabel("就绪");
    //图表相关
    private final DefaultCategoryDataset trafficDataset = new DefaultCategoryDataset();
    private long lastTotalBytes = 0;

    //定时器
    private final Timer analysisTimer = new Timer(1000, e -> updateAnalysis());
    private final ScheduledExecutorService chartExecutor = Executors.newSingleThreadScheduledExecutor();

    private static final int SCROLL_DELAY = 200; // 200ms节流
    private volatile long lastScrollTime = 0;

    private JPanel analysisPanel;
    private JLabel protocolLabel;
    private JLabel trafficLabel;


    private JScrollPane scrollPane;
    private JTable packetTable;
    private boolean autoScroll = true;

    public MainFrame() {
        initComponents();
        loadNetworkDevices();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setLocationRelativeTo(null);
        tableModel.addDataUpdateListener(this); // 注册监听
        analysisTimer.start(); // 启动定时更新
    }

    private void updateAnalysis() {
        if (captureService == null) return;
        NetworkAnalyzer analyzer = captureService.getAnalyzer();
        if (analyzer != null) {
            // 更新协议分布
            double mb = analyzer.getTotalBytes() / (1024.0 * 1024.0);
            String protocolText = analyzer.getProtocolDistribution().entrySet().stream()
                    .map(e -> e.getKey() + ": " + e.getValue())
                    .collect(Collectors.joining(", "));
            protocolLabel.setText("协议分布: " + protocolText);
            trafficLabel.setText(String.format("总流量: %.2f MB", mb));

            // 更新流量统计

            trafficLabel.setText(String.format("总流量: %.2f MB", mb));
        }else{
            protocolLabel.setText("协议分布: 等待数据...");
            trafficLabel.setText("总流量: 初始化中");
        }
    }
    @Override
    public void onDataAdded(int count) {
        long now = System.currentTimeMillis();
        if (now - lastScrollTime > SCROLL_DELAY) {
            scrollToBottom();
            lastScrollTime = now;
        }
    }

    private void initComponents() {
        setTitle("网络抓包分析系统");
        setSize(1200, 800);
        setLayout(new BorderLayout(10, 10));
        
        packetTable = new JTable(tableModel) {
            // 禁用单元格绘制器缓存
            public boolean getScrollableTracksViewportWidth() {
                return getPreferredSize().width < getParent().getWidth();
            }
        };
        packetTable.setAutoCreateRowSorter(false);
        packetTable.setFillsViewportHeight(false);
        packetTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        JPopupMenu popup = new JPopupMenu();
        JCheckBoxMenuItem autoScrollItem = new JCheckBoxMenuItem("自动滚动", true);
        autoScrollItem.addActionListener(e -> autoScroll = autoScrollItem.isSelected());
        popup.add(autoScrollItem);

        packetTable.setComponentPopupMenu(popup);

        // 设备选择组件
        deviceCombo = new JComboBox<>();
        JButton refreshBtn = new JButton("刷新");
        refreshBtn.addActionListener(e -> loadNetworkDevices());

        // 控制按钮
        JButton startBtn = new JButton(startCaptureAction());
        JButton stopBtn = new JButton(stopCaptureAction());

        // 控制面板
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.add(new JLabel("网卡选择:"));
        controlPanel.add(deviceCombo);
        controlPanel.add(refreshBtn);
        controlPanel.add(startBtn);
        controlPanel.add(stopBtn);

        // 数据表格
        JTable packetTable = new JTable(tableModel);
        JScrollPane scrollPane = new JScrollPane(packetTable);

        // 主布局
        setLayout(new BorderLayout());
        add(controlPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);

        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.add(new JLabel("状态:"));
        statusPanel.add(statusLabel);

        packetTable = new JTable(tableModel);
        scrollPane = new JScrollPane(packetTable);
        add(statusPanel, BorderLayout.SOUTH);

        scrollPane.getVerticalScrollBar().addAdjustmentListener(e -> {
            JScrollBar bar = (JScrollBar)e.getSource();
            autoScroll = (bar.getValue() + bar.getVisibleAmount()) == bar.getMaximum();
        });

        // 创建分析面板
        analysisPanel = new JPanel(new GridLayout(2,1));

        // 协议分布显示
        protocolLabel = new JLabel("协议分布: 加载中...");
        analysisPanel.add(protocolLabel);

        // 流量统计显示
        trafficLabel = new JLabel("总流量: 0 MB");
        analysisPanel.add(trafficLabel);

        // 将分析面板添加到主界面
        add(analysisPanel, BorderLayout.EAST);


    }

    private Action startCaptureAction() {
        return new AbstractAction("开始抓包") {
            @Override
            public void actionPerformed(ActionEvent e) {
                NetworkInterfaceWrapper selected = (NetworkInterfaceWrapper) deviceCombo.getSelectedItem();
                if (selected != null) {
                    // 修改为传递两个参数
                    captureService = new PacketCaptureService(tableModel, MainFrame.this);
                    captureService.startCapture(selected);
                    updateStatus("抓包已启动 - 正在捕获: " + selected.toString());
                }
            }
        };
    }
    private void scrollToBottom() {
        if (!autoScroll) return;

        SwingUtilities.invokeLater(() -> {
            JScrollBar vertical = scrollPane.getVerticalScrollBar();
            if (vertical.getValue() + vertical.getVisibleAmount() >= vertical.getMaximum() - 100) {
                int lastRow = tableModel.getRowCount() - 1;
                if (lastRow >= 0) {
                    Rectangle rect = packetTable.getCellRect(lastRow, 0, true);
                    packetTable.scrollRectToVisible(rect);
                }
            }
        });
    }

    private Action stopCaptureAction() {  // 添加缺失的方法
        return new AbstractAction("停止抓包") {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (captureService != null) {
                    captureService.stopCapture();
                }
            }
        };
    }

    private void loadNetworkDevices() {
        deviceCombo.removeAllItems();
        controller.getAvailableDevices().forEach(deviceCombo::addItem);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MainFrame().setVisible(true));
    }
    public void updateStatus(String message) {
        SwingUtilities.invokeLater(() ->
                statusLabel.setText(message)
        );
    }
}


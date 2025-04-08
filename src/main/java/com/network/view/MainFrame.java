package com.network.view;

import com.network.controller.NetworkController;
import com.network.model.NetworkInterfaceWrapper;
import com.network.service.NetworkAnalyzer;
import com.network.service.PacketCaptureService;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.general.PieDataset;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;


import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.text.DecimalFormat;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;


/**
 * 主界面框架
 * 负责用户界面展示和事件处理
 */
public class MainFrame extends JFrame implements PacketTableModel.DataUpdateListener {
    // region 成员变量
    // 核心组件
    private final NetworkController controller = new NetworkController();
    private final PacketTableModel tableModel = new PacketTableModel();
    private JComboBox<NetworkInterfaceWrapper> deviceCombo;
    private PacketCaptureService captureService;
    private JLabel statusLabel = new JLabel("就绪");

    // 图表相关
    private final DefaultCategoryDataset trafficDataset = new DefaultCategoryDataset();
    private long lastTotalBytes = 0;

    // 定时器与线程
    private final Timer analysisTimer = new Timer(1000, e -> updateAnalysis());
    private final ScheduledExecutorService chartExecutor = Executors.newSingleThreadScheduledExecutor();

    // 界面组件
    private static final int SCROLL_DELAY = 200;
    private volatile long lastScrollTime = 0;
    private JPanel analysisPanel;
    private JLabel protocolLabel;
    private JLabel trafficLabel;
    private JScrollPane scrollPane;
    private JTable packetTable;
    private boolean autoScroll = true;

    //图表
    private JFreeChart trafficChart;
    private ChartPanel trafficChartPanel;
    private JFreeChart protocolChart;
    private ChartPanel protocolChartPanel;

    // endregion

    // region 构造函数
    public MainFrame() {
        initComponents();
        loadNetworkDevices();
        setupFrame();
        tableModel.addDataUpdateListener(this);
        analysisTimer.start();
    }
    // endregion

    // region 界面初始化
    /**
     * 初始化界面组件
     */
    private void initComponents() {
        setTitle("网络抓包分析系统");
        setSize(1200, 800);
        setLayout(new BorderLayout(10, 10));

        initTable();
        initControlPanel();
        initStatusPanel();
        initAnalysisPanel();

        initTrafficChart();
        initProtocolChart();

        // 创建主布局分割面板
        JSplitPane mainSplitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                scrollPane,        // 左侧表格
                createChartPanel() // 右侧图表
        );
        mainSplitPane.setDividerLocation(800); // 初始分隔位置
        mainSplitPane.setResizeWeight(0.7);    // 左侧占70%宽度

        add(mainSplitPane, BorderLayout.CENTER);
    }
    private JPanel createChartPanel() {
        JPanel chartPanel = new JPanel(new GridLayout(2, 1));

        JPanel trafficPanel = new JPanel(new BorderLayout());
        trafficPanel.add(trafficChartPanel, BorderLayout.CENTER);
        trafficPanel.setPreferredSize(new Dimension(600, 300));

        JPanel protocolPanel = new JPanel(new BorderLayout());
        protocolPanel.add(protocolChartPanel, BorderLayout.CENTER);
        protocolPanel.setPreferredSize(new Dimension(600, 300));

        chartPanel.add(trafficPanel);
        chartPanel.add(protocolPanel);

        return chartPanel;
    }

    /**
     * 初始化数据表格
     */
    private void initTable() {
        packetTable = new JTable(tableModel) {
            @Override
            public boolean getScrollableTracksViewportWidth() {
                return getPreferredSize().width < getParent().getWidth();
            }
        };
        packetTable.setAutoCreateRowSorter(false);
        packetTable.setFillsViewportHeight(false);
        packetTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // 右键菜单设置
        JPopupMenu popup = new JPopupMenu();
        JCheckBoxMenuItem autoScrollItem = new JCheckBoxMenuItem("自动滚动", true);
        autoScrollItem.addActionListener(e -> autoScroll = autoScrollItem.isSelected());
        popup.add(autoScrollItem);
        packetTable.setComponentPopupMenu(popup);

        scrollPane = new JScrollPane(packetTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * 初始化控制面板
     */
    private void initControlPanel() {
        // 设备选择组件
        deviceCombo = new JComboBox<>();
        JButton refreshBtn = new JButton("刷新");
        refreshBtn.addActionListener(e -> loadNetworkDevices());

        // 控制按钮
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.add(new JLabel("网卡选择:"));
        controlPanel.add(deviceCombo);
        controlPanel.add(refreshBtn);
        controlPanel.add(new JButton(startCaptureAction()));
        controlPanel.add(new JButton(pauseCaptureAction()));
        controlPanel.add(new JButton(stopCaptureAction()));

        add(controlPanel, BorderLayout.NORTH);
    }

    /**
     * 初始化状态面板
     */
    private void initStatusPanel() {
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.add(new JLabel("状态:"));
        statusPanel.add(statusLabel);
        add(statusPanel, BorderLayout.SOUTH);
    }

    /**
     * 初始化分析面板
     */
    private void initAnalysisPanel() {
        analysisPanel = new JPanel(new GridLayout(2, 1));
        protocolLabel = new JLabel("协议分布: 加载中...");
        trafficLabel = new JLabel("总流量: 0 MB");
        analysisPanel.add(protocolLabel);
        analysisPanel.add(trafficLabel);
        add(analysisPanel, BorderLayout.EAST);
    }

    /**
     * 初始化图表
     */
    private void initTrafficChart() {
        // 创建数据集和图表
        TimeSeries series = new TimeSeries("实时流量");
        TimeSeriesCollection dataset = new TimeSeriesCollection(series);

        trafficChart = ChartFactory.createTimeSeriesChart(
                "实时流量趋势", "时间", "速率 (KB/s)", dataset,
                true, true, false
        );

        // 设置全局抗锯齿
        trafficChart.setTextAntiAlias(true);
        trafficChart.setAntiAlias(true);

        // 标题字体（备用字体方案）
        trafficChart.getTitle().setFont(new Font("宋体", Font.BOLD, 16));

        XYPlot plot = trafficChart.getXYPlot();
        // 坐标轴标签字体
        plot.getDomainAxis().setLabelFont(new Font("宋体", Font.PLAIN, 12));
        plot.getRangeAxis().setLabelFont(new Font("宋体", Font.PLAIN, 12));

        // 刻度字体
        plot.getDomainAxis().setTickLabelFont(new Font("宋体", Font.PLAIN, 10));
        plot.getRangeAxis().setTickLabelFont(new Font("宋体", Font.PLAIN, 10));

        // 图例字体（如果存在）
        if (trafficChart.getLegend() != null) {
            trafficChart.getLegend().setItemFont(new Font("宋体", Font.PLAIN, 12));
        }

        // 背景与样式
        plot.setBackgroundPaint(Color.WHITE);
        plot.getDomainAxis().setAutoRange(true);
        plot.getDomainAxis().setFixedAutoRange(60000);

        trafficChartPanel = new ChartPanel(trafficChart);
        trafficChartPanel.setPreferredSize(new Dimension(600, 300));
    }
    private void initProtocolChart() {
        DefaultPieDataset dataset = new DefaultPieDataset();

        protocolChart = ChartFactory.createPieChart(
                "协议分布", dataset,
                true, true, false
        );

        // 全局抗锯齿
        protocolChart.setTextAntiAlias(true);
        protocolChart.setAntiAlias(true);

        // 标题字体
        protocolChart.getTitle().setFont(new Font("宋体", Font.BOLD, 16));

        // 饼图样式
        PiePlot plot = (PiePlot) protocolChart.getPlot();
        plot.setLabelFont(new Font("宋体", Font.PLAIN, 12));

        // 自定义标签生成器（解决百分比显示问题）
        plot.setLabelGenerator(new StandardPieSectionLabelGenerator(
                "{0}: {1} ({2})",
                new DecimalFormat("0"),
                new DecimalFormat("0%")
        ) {
            public Font getSectionLabelFont(int section) {
                return new Font("宋体", Font.PLAIN, 12);
            }
        });

        // 颜色预设
        plot.setSectionPaint("TCP", new Color(59, 65, 198));
        plot.setSectionPaint("UDP", new Color(89, 187, 131));

        protocolChartPanel = new ChartPanel(protocolChart);
        protocolChartPanel.setPreferredSize(new Dimension(400, 300));
    }

    /**
     * 框架通用设置
     */
    private void setupFrame() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setLocationRelativeTo(null);
    }
    // endregion

    // region 业务逻辑
    /**
     * 更新分析数据（每秒执行）
     */
    private void updateAnalysis() {
        if (captureService == null) return;

        NetworkAnalyzer analyzer = captureService.getAnalyzer();
        if (analyzer != null) {
            updateProtocolDistribution(analyzer);
            updateTrafficStatistics(analyzer);
        } else {
            protocolLabel.setText("协议分布: 等待数据...");
            trafficLabel.setText("总流量: 初始化中");
        }
    }

    /**
     * 更新协议分布信息
     */
    private void updateProtocolDistribution(NetworkAnalyzer analyzer) {
        // 修改为正确的数据集获取方式
        PieDataset dataset = ((PiePlot) protocolChart.getPlot()).getDataset();

        if (dataset instanceof DefaultPieDataset) {
            DefaultPieDataset pieDataset = (DefaultPieDataset) dataset;
            pieDataset.clear();

            analyzer.getProtocolDistribution().forEach((proto, count) -> {
                pieDataset.setValue(proto, count);
            });

            protocolLabel.setText("协议分布: " + analyzer.getProtocolDistribution().toString());
        }
    }

    /**
     * 更新流量统计信息
     */
    private void updateTrafficStatistics(NetworkAnalyzer analyzer) {
        long currentBytes = analyzer.getTotalBytes();
        double rateKBps = (currentBytes - lastTotalBytes) / 1024.0;
        lastTotalBytes = currentBytes;

        TimeSeries series = ((TimeSeriesCollection) trafficChart.getXYPlot().getDataset()).getSeries(0);
        series.addOrUpdate(new Millisecond(), rateKBps);

        SwingUtilities.invokeLater(() -> {
            trafficChart.fireChartChanged();
            trafficChartPanel.repaint();
        });

        double totalMB = currentBytes / (1024.0 * 1024.0);
        trafficLabel.setText(String.format("总流量: %.2f MB", totalMB));
    }

    /**
     * 滚动到底部（节流控制）
     */
    private void scrollToBottom() {
        if (!autoScroll) return;

        SwingUtilities.invokeLater(() -> {
            JScrollBar vertical = scrollPane.getVerticalScrollBar();
            if ((vertical.getValue() + vertical.getVisibleAmount()) >= vertical.getMaximum() - 100) {
                int lastRow = tableModel.getRowCount() - 1;
                if (lastRow >= 0) {
                    packetTable.scrollRectToVisible(packetTable.getCellRect(lastRow, 0, true));
                }
            }
        });
    }
    // endregion

    // region 事件处理
    @Override
    public void onDataAdded(int count) {
        long now = System.currentTimeMillis();
        if (now - lastScrollTime > SCROLL_DELAY) {
            scrollToBottom();
            lastScrollTime = now;
        }
    }

    /**
     * 开始/继续抓包动作
     */
    private Action startCaptureAction() {
        return new AbstractAction("开始/继续抓包") {
            @Override
            public void actionPerformed(ActionEvent e) {
                NetworkInterfaceWrapper selected = (NetworkInterfaceWrapper) deviceCombo.getSelectedItem();
                if (selected != null) {
                    if (captureService == null) {
                        captureService = new PacketCaptureService(tableModel, MainFrame.this);
                    }
                    captureService.startCapture(selected);
                    updateStatus("抓包已启动 - 正在捕获: " + selected);
                }
            }
        };
    }

    /**
     * 暂停抓包动作
     */
    private Action pauseCaptureAction() {
        return new AbstractAction("暂停抓包") {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (captureService != null) {
                    captureService.pauseCapture();
                }
            }
        };
    }

    /**
     * 停止抓包动作
     */
    private Action stopCaptureAction() {
        return new AbstractAction("停止抓包") {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (captureService != null) {
                    captureService.stopCapture();
                }
            }
        };
    }
    // endregion

    // region 工具方法
    /**
     * 加载网络设备列表
     */
    private void loadNetworkDevices() {
        deviceCombo.removeAllItems();
        controller.getAvailableDevices().forEach(deviceCombo::addItem);
    }

    /**
     * 更新状态栏信息
     */
    public void updateStatus(String message) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MainFrame().setVisible(true));
    }
    // endregion
}
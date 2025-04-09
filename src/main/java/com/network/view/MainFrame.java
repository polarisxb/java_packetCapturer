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
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.text.DecimalFormat;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

/**
 * 主界面框架
 * 提供完整的网络抓包分析系统用户界面，主要功能包括：
 * 1. 网络接口设备选择
 * 2. 数据包捕获控制（启动/暂停/停止）
 * 3. 实时数据包表格展示
 * 4. 协议分布和流量趋势可视化
 *
 * 线程安全设计：
 * - SwingUtilities保证界面更新线程安全
 * - 定时器使用Swing Timer
 * - 后台任务使用ScheduledExecutorService
 */
public class MainFrame extends JFrame implements PacketTableModel.DataUpdateListener {

    // region ====================== 成员变量 ======================

    // 核心组件
    private final NetworkController controller = new NetworkController();
    private final PacketTableModel tableModel = new PacketTableModel();
    private JComboBox<NetworkInterfaceWrapper> deviceCombo;
    private PacketCaptureService captureService;
    private JLabel statusLabel = new JLabel("就绪");

    // 图表数据相关
    private final DefaultCategoryDataset trafficDataset = new DefaultCategoryDataset();
    private long lastTotalBytes = 0;

    // 定时任务管理
    private final Timer analysisTimer = new Timer(1000, e -> updateAnalysis());
    private final ScheduledExecutorService chartExecutor = Executors.newSingleThreadScheduledExecutor();

    // 界面组件参数
    private static final int SCROLL_DELAY = 200;
    private volatile long lastScrollTime = 0;
    private JPanel analysisPanel;
    private JTextArea protocolLabel;
    private JLabel trafficLabel;
    private JScrollPane scrollPane;
    private JTable packetTable;
    private boolean autoScroll = true;

    // 图表组件
    private JFreeChart trafficChart;
    private ChartPanel trafficChartPanel;
    private JFreeChart protocolChart;
    private ChartPanel protocolChartPanel;

    // endregion

    // region ====================== 构造函数 ======================

    /**
     * 主界面构造函数
     * 执行初始化流程：
     * 1. 界面组件初始化
     * 2. 网络设备加载
     * 3. 窗口设置
     * 4. 启动定时任务
     */
    public MainFrame() {
        initComponents();
        loadNetworkDevices();
        setupFrame();
        tableModel.addDataUpdateListener(this);
        analysisTimer.start();
    }

    // endregion

    // region ====================== 界面初始化方法 ======================

    /**
     * 初始化所有界面组件
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

        // 主分割面板布局
        JSplitPane mainSplitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                scrollPane,        // 左侧数据表格
                createChartPanel() // 右侧图表面板
        );
        mainSplitPane.setDividerLocation(800); // 初始分割位置
        mainSplitPane.setResizeWeight(0.6);    // 分配比例

        add(mainSplitPane, BorderLayout.CENTER);
    }

    /**
     * 创建图表容器面板
     */
    private JPanel createChartPanel() {
        JPanel chartPanel = new JPanel(new GridLayout(2, 1));

        // 流量趋势图面板
        JPanel trafficPanel = new JPanel(new BorderLayout());
        trafficPanel.add(trafficChartPanel, BorderLayout.CENTER);
        trafficPanel.setPreferredSize(new Dimension(600, 300));

        // 协议分布图面板
        JPanel protocolPanel = new JPanel(new BorderLayout());
        protocolPanel.add(protocolChartPanel, BorderLayout.CENTER);
        protocolPanel.setPreferredSize(new Dimension(600, 300));

        chartPanel.add(trafficPanel);
        chartPanel.add(protocolPanel);

        return chartPanel;
    }

    /**
     * 初始化数据表格组件
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

        // 右键上下文菜单
        JPopupMenu popup = new JPopupMenu();
        JCheckBoxMenuItem autoScrollItem = new JCheckBoxMenuItem("自动滚动", true);
        autoScrollItem.addActionListener(e -> autoScroll = autoScrollItem.isSelected());
        popup.add(autoScrollItem);
        packetTable.setComponentPopupMenu(popup);

        scrollPane = new JScrollPane(packetTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * 初始化控制面板（顶部栏）
     */
    private void initControlPanel() {
        // 设备选择组件
        deviceCombo = new JComboBox<>();
        JButton refreshBtn = new JButton("刷新");
        refreshBtn.addActionListener(e -> loadNetworkDevices());

        // 控制按钮布局
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
     * 初始化状态面板（底部栏）
     */
    private void initStatusPanel() {
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.add(new JLabel("状态:"));
        statusPanel.add(statusLabel);
        add(statusPanel, BorderLayout.SOUTH);
    }

    /**
     * 初始化分析面板（右侧边栏）
     */
    private void initAnalysisPanel() {
        analysisPanel = new JPanel();
        analysisPanel.setLayout(new BoxLayout(analysisPanel, BoxLayout.Y_AXIS));
        analysisPanel.setBorder(BorderFactory.createTitledBorder("实时统计"));

        // 协议分布文本组件
        protocolLabel = new JTextArea("协议分布: 加载中...");
        protocolLabel.setLineWrap(true);
        protocolLabel.setWrapStyleWord(true);
        protocolLabel.setEditable(false);
        protocolLabel.setBackground(UIManager.getColor("Label.background"));

        // 总流量标签
        trafficLabel = new JLabel("总流量: 0 MB");

        // 组件尺寸限制
        protocolLabel.setMaximumSize(new Dimension(200, Integer.MAX_VALUE));
        trafficLabel.setMaximumSize(new Dimension(200, 30));

        // 添加滚动容器
        JScrollPane protocolScroll = new JScrollPane(protocolLabel);
        protocolScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        protocolScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        analysisPanel.add(protocolScroll);
        analysisPanel.add(trafficLabel);

        add(analysisPanel, BorderLayout.EAST);
    }

    /**
     * 初始化实时流量趋势图
     */
    private void initTrafficChart() {
        // 创建时间序列数据集
        TimeSeries series = new TimeSeries("实时流量");
        TimeSeriesCollection dataset = new TimeSeriesCollection(series);

        // 创建折线图
        trafficChart = ChartFactory.createTimeSeriesChart(
                "实时流量趋势",
                "时间",
                "速率 (KB/s)",
                dataset,
                true,
                true,
                false
        );

        // 全局抗锯齿设置
        trafficChart.setTextAntiAlias(true);
        trafficChart.setAntiAlias(true);

        // 标题字体设置
        trafficChart.getTitle().setFont(new Font("宋体", Font.BOLD, 16));

        // 获取绘图区域
        XYPlot plot = trafficChart.getXYPlot();

        // 坐标轴字体设置
        plot.getDomainAxis().setLabelFont(new Font("宋体", Font.PLAIN, 12));
        plot.getRangeAxis().setLabelFont(new Font("宋体", Font.PLAIN, 12));

        // 刻度字体设置
        plot.getDomainAxis().setTickLabelFont(new Font("宋体", Font.PLAIN, 10));
        plot.getRangeAxis().setTickLabelFont(new Font("宋体", Font.PLAIN, 10));

        // 图例字体设置
        if (trafficChart.getLegend() != null) {
            trafficChart.getLegend().setItemFont(new Font("宋体", Font.PLAIN, 12));
        }

        // 绘图区域样式
        plot.setBackgroundPaint(Color.WHITE);
        plot.getDomainAxis().setAutoRange(true);
        plot.getDomainAxis().setFixedAutoRange(60000); // 60秒时间窗口

        trafficChartPanel = new ChartPanel(trafficChart);
        trafficChartPanel.setPreferredSize(new Dimension(600, 300));
    }

    /**
     * 初始化协议分布饼图
     */
    private void initProtocolChart() {
        DefaultPieDataset dataset = new DefaultPieDataset();

        // 创建饼图
        protocolChart = ChartFactory.createPieChart(
                "协议分布",
                dataset,
                true,
                true,
                false
        );

        // 全局抗锯齿设置
        protocolChart.setTextAntiAlias(true);
        protocolChart.setAntiAlias(true);

        // 标题字体设置
        protocolChart.getTitle().setFont(new Font("宋体", Font.BOLD, 16));

        // 获取饼图绘图区域
        PiePlot plot = (PiePlot) protocolChart.getPlot();
        plot.setLabelFont(new Font("宋体", Font.PLAIN, 12));

        // 自定义标签格式
        plot.setLabelGenerator(new StandardPieSectionLabelGenerator(
                "{0}: {1} ({2})",
                new DecimalFormat("0"),      // 数值格式
                new DecimalFormat("0%")      // 百分比格式
        ));

        // 预定义颜色方案
        plot.setSectionPaint("TCP", new Color(251, 247, 3));   // 亮黄色
        plot.setSectionPaint("UDP", new Color(89, 187, 131));  // 青绿色

        protocolChartPanel = new ChartPanel(protocolChart);
        protocolChartPanel.setPreferredSize(new Dimension(400, 300));
    }

    /**
     * 设置窗口通用属性
     */
    private void setupFrame() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setLocationRelativeTo(null); // 窗口居中
    }

    // endregion

    // region ====================== 业务逻辑方法 ======================

    /**
     * 更新分析数据（定时任务入口）
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
     * 更新协议分布显示
     */
    private void updateProtocolDistribution(NetworkAnalyzer analyzer) {
        Map<String, Long> stats = analyzer.getProtocolDistribution();
        DefaultPieDataset pieDataset = (DefaultPieDataset) ((PiePlot) protocolChart.getPlot()).getDataset();

        pieDataset.clear(); // 清空旧数据

        // 填充协议数据
        stats.forEach((proto, count) -> {
            if (count > 0) {
                pieDataset.setValue(proto, count);
            }
        });

        // 生成协议分布文本
        String displayText = stats.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5)
                .map(e -> e.getKey() + ": " + e.getValue())
                .collect(Collectors.joining(", "))
                + (stats.size() > 5 ? "\n(更多协议...)" : "");

        // 线程安全更新界面
        SwingUtilities.invokeLater(() -> {
            protocolLabel.setText("协议分布:\n" + displayText);
            protocolChart.fireChartChanged();
        });
    }

    /**
     * 更新流量统计信息
     */
    private void updateTrafficStatistics(NetworkAnalyzer analyzer) {
        long currentBytes = analyzer.getTotalBytes();
        double rateKBps = (currentBytes - lastTotalBytes) / 1024.0;
        lastTotalBytes = currentBytes;

        // 更新时间序列数据
        TimeSeries series = ((TimeSeriesCollection) trafficChart.getXYPlot().getDataset()).getSeries(0);
        series.addOrUpdate(new Millisecond(), rateKBps);

        // 线程安全更新界面
        SwingUtilities.invokeLater(() -> {
            trafficChart.fireChartChanged();
            trafficChartPanel.repaint();
            trafficLabel.setText(String.format("总流量: %.2f MB", currentBytes / (1024.0 * 1024.0)));
        });
    }

    /**
     * 自动滚动到底部（节流控制）
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

    // region ====================== 事件处理方法 ======================

    /**
     * 数据更新事件回调
     */
    @Override
    public void onDataAdded(int count) {
        long now = System.currentTimeMillis();
        if (now - lastScrollTime > SCROLL_DELAY) {
            scrollToBottom();
            lastScrollTime = now;
        }
    }

    /**
     * 创建开始/继续抓包动作
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
     * 创建暂停抓包动作
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
     * 创建停止抓包动作
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

    // region ====================== 工具方法 ======================

    /**
     * 加载网络设备到下拉框
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

    /**
     * 程序入口
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MainFrame().setVisible(true));
    }

    // endregion
}
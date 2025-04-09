package com.network.service;

import com.network.model.NetworkInterfaceWrapper;
import com.network.model.PacketRecord;
import com.network.view.MainFrame;
import com.network.view.PacketTableModel;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 网络数据包捕获服务核心类
 * 提供完整的抓包生命周期管理，包含以下功能：
 * 1. 网络接口设备管理
 * 2. 抓包线程控制（启动/暂停/停止）
 * 3. 多协议解析（IP/TCP/UDP/HTTP）
 * 4. 数据分发（界面更新和统计分析）
 *
 * 线程安全设计：
 * - 使用volatile保证状态标志可见性
 * - 独立抓包线程避免阻塞UI
 * - SwingUtilities保证界面更新线程安全
 */
public class PacketCaptureService {

    // region ====================== 成员变量 ======================

    /**
     * Pcap4j抓包句柄（线程封闭在抓包线程中使用）
     */
    private PcapHandle handle;

    /**
     * 数据分析器（线程安全）
     */
    private final NetworkAnalyzer analyzer = new NetworkAnalyzer();

    /**
     * 抓包状态标志（volatile保证多线程可见性）
     */
    private volatile boolean isCapturing = false;

    /**
     * 当前绑定的网络设备包装对象
     */
    private NetworkInterfaceWrapper currentDevice;

    /**
     * 抓包工作线程实例
     */
    private Thread captureThread;

    // 界面交互相关
    /**
     * 数据表格模型（通过SwingUtilities线程安全更新）
     */
    private final PacketTableModel tableModel;

    /**
     * 主界面引用（用于状态栏更新）
     */
    private final MainFrame mainFrame;

    // 性能调优参数
    /**
     * 批量处理最大包数（平衡内存和UI刷新频率）
     */
    private static final int MAX_BATCH_SIZE = 200;

    /**
     * 缓冲区强制刷新间隔（单位：毫秒）
     */
    private static final int BUFFER_FLUSH_INTERVAL = 500;

    /**
     * 最大缓冲时间窗口（单位：毫秒）
     */
    private static final long MAX_BUFFER_TIME = 300;

    // endregion

    // region ====================== 构造函数 ======================

    /**
     * 构造抓包服务实例
     * @param tableModel 数据表格模型（必须非null）
     * @param mainFrame 主界面引用（必须非null）
     */
    public PacketCaptureService(PacketTableModel tableModel, MainFrame mainFrame) {
        this.tableModel = tableModel;
        this.mainFrame = mainFrame;
    }

    // endregion

    // region ====================== 公共控制方法 ======================

    /**
     * 获取数据分析器实例
     * @return 已初始化的分析器对象（始终非null）
     */
    public NetworkAnalyzer getAnalyzer() {
        return analyzer;
    }

    /**
     * 启动/恢复数据包捕获
     * @param device 选择的网络接口设备（允许为null，使用当前设备）
     *
     * 执行流程：
     * 1. 设备变更检查
     * 2. 资源重新初始化
     * 3. 启动抓包线程
     */
    public void startCapture(NetworkInterfaceWrapper device) {
        try {
            // 设备变更检查与资源初始化
            if (needReinitializeHandle(device)) {
                closeExistingHandle();
                initializeNewHandle(device);
            }

            // 确保单一线程运行
            if (isCaptureThreadRunning()) {
                return;
            }

            // 启动新的抓包线程
            startCaptureThread();
        } catch (Exception e) {
            handleException(e);
        }
    }

    /**
     * 暂停数据包捕获（保持网络接口打开）
     */
    public void pauseCapture() {
        isCapturing = false;
        mainFrame.updateStatus("抓包已暂停");
    }

    /**
     * 完全停止抓包并释放资源
     */
    public void stopCapture() {
        isCapturing = false;
        closeCaptureHandle();
        mainFrame.updateStatus("抓包已停止");
    }

    /**
     * 获取当前捕获状态
     * @return true表示正在抓包
     */
    public boolean isCapturing() {
        return isCapturing;
    }

    // endregion

    // region ====================== 核心抓包逻辑 ======================

    /**
     * 抓包主循环（运行在独立线程中）
     *
     * 工作流程：
     * 1. 初始化数据缓冲区
     * 2. 循环获取数据包
     * 3. 解析并缓存数据
     * 4. 条件触发缓冲区刷新
     */
    private void captureLoop() {
        List<PacketRecord> buffer = new ArrayList<>(MAX_BATCH_SIZE);
        long lastFlushTime = System.currentTimeMillis();

        while (isCapturing) {
            try {
                Packet packet = handle.getNextPacketEx();
                if (packet == null) continue;

                // 协议解析与记录生成
                processPacket(packet, buffer);

                // 缓冲区刷新条件判断
                if (shouldFlushBuffer(buffer, lastFlushTime)) {
                    flushBuffer(buffer);
                    lastFlushTime = System.currentTimeMillis();
                }
            } catch (Exception e) {
                handleCaptureError(e);
            }
        }

        // 退出前强制刷新剩余数据
        flushBuffer(buffer);
    }

    /**
     * 处理单个数据包
     * @param packet 原始数据包对象
     * @param buffer 目标缓冲区（线程封闭，仅在抓包线程访问）
     */
    private void processPacket(Packet packet, List<PacketRecord> buffer) {
        PacketRecord record = parsePacket(packet);
        analyzer.analyze(record);
        buffer.add(record);
    }

    // endregion

    // region ====================== 协议解析逻辑 ======================

    /**
     * 解析原始数据包为业务对象
     * @param packet Pcap4j原始数据包对象
     * @return 格式化后的数据包记录
     */
    private PacketRecord parsePacket(Packet packet) {
        PacketRecord.Builder builder = new PacketRecord.Builder(
                Instant.now(),
                packet.length(),
                packet
        );

        // 分层解析协议
        parseTransportLayer(packet, builder);
        parseNetworkLayer(packet, builder);

        return builder.build();
    }

    /**
     * 解析传输层协议（TCP/UDP）
     * @param packet 原始数据包对象
     * @param builder 数据包记录建造者
     */
    private void parseTransportLayer(Packet packet, PacketRecord.Builder builder) {
        // TCP协议处理
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            builder.srcPort(tcp.getHeader().getSrcPort().value())
                    .dstPort(tcp.getHeader().getDstPort().value())
                    .protocol("TCP");

            // HTTP负载解析
            parseHttpPayload(tcp, builder);
        }
        // UDP协议处理
        else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            builder.srcPort(udp.getHeader().getSrcPort().value())
                    .dstPort(udp.getHeader().getDstPort().value())
                    .protocol("UDP");
        }
    }

    /**
     * 解析网络层协议（IP）
     */
    private void parseNetworkLayer(Packet packet, PacketRecord.Builder builder) {
        if (packet.contains(IpPacket.class)) {
            IpPacket ip = packet.get(IpPacket.class);
            builder.srcIp(ip.getHeader().getSrcAddr().getHostAddress())
                    .dstIp(ip.getHeader().getDstAddr().getHostAddress())
                    .protocol(ip.getHeader().getProtocol().name());
        }
    }

    /**
     * 解析HTTP协议内容（基于TCP负载）
     * @param tcp TCP数据包对象
     * @param builder 数据包记录建造者
     */
    private void parseHttpPayload(TcpPacket tcp, PacketRecord.Builder builder) {
        if (tcp.getPayload() == null) return;

        byte[] payload = tcp.getPayload().getRawData();
        if (payload == null || payload.length == 0) return;

        try {
            String payloadStr = new String(payload, StandardCharsets.US_ASCII).trim();

            // 请求方法检测
            if (payloadStr.startsWith("GET") || payloadStr.startsWith("POST") ||
                    payloadStr.startsWith("PUT") || payloadStr.startsWith("DELETE")) {
                parseHttpRequest(payloadStr, builder);
            }
            // 响应检测
            else if (payloadStr.startsWith("HTTP/")) {
                parseHttpResponse(payloadStr, builder);
            }
        } catch (Exception e) {
            // 忽略非HTTP数据或编码异常
        }
    }

    // endregion

    // region ====================== 界面交互方法 ======================

    /**
     * 刷新缓冲区到界面表格
     * @param buffer 待刷新的数据包记录集合
     */
    private void flushBuffer(List<PacketRecord> buffer) {
        if (buffer.isEmpty()) return;

        // 创建数据副本避免并发修改
        List<PacketRecord> copy = new ArrayList<>(buffer);
        buffer.clear();

        // 线程安全更新界面
        SwingUtilities.invokeLater(() -> {
            tableModel.addPackets(copy);
            mainFrame.updateStatus("已捕获: " + tableModel.getRowCount() + " 个包");
        });
    }

    // endregion

    // region ====================== 工具方法 ======================

    /**
     * 判断缓冲区是否需要刷新
     * @param buffer 当前缓冲区
     * @param lastFlushTime 上次刷新时间戳
     * @return true表示需要立即刷新
     */
    private boolean shouldFlushBuffer(List<PacketRecord> buffer, long lastFlushTime) {
        return buffer.size() >= MAX_BATCH_SIZE ||
                (System.currentTimeMillis() - lastFlushTime) > MAX_BUFFER_TIME;
    }

    /**
     * 统一异常处理
     * @param e 捕获的异常对象
     */
    private void handleException(Exception e) {
        mainFrame.updateStatus("捕获错误: " + e.getMessage());
    }

    // endregion

    // region ====================== 私有辅助方法 ======================

    /**
     * 判断是否需要重新初始化抓包句柄
     */
    private boolean needReinitializeHandle(NetworkInterfaceWrapper device) {
        return handle == null ||
                !handle.isOpen() ||
                currentDevice == null ||
                !currentDevice.equals(device);
    }

    /**
     * 关闭现有抓包句柄
     */
    private void closeExistingHandle() throws NotOpenException {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    /**
     * 初始化新抓包句柄
     */
    private void initializeNewHandle(NetworkInterfaceWrapper device) throws PcapNativeException {
        PcapNetworkInterface nif = device.getPcapDevice();
        handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        currentDevice = device;
    }

    /**
     * 检查抓包线程是否运行中
     */
    private boolean isCaptureThreadRunning() {
        return captureThread != null && captureThread.isAlive();
    }

    /**
     * 启动新的抓包线程
     */
    private void startCaptureThread() {
        isCapturing = true;
        captureThread = new Thread(this::captureLoop);
        captureThread.setDaemon(true); // 设置为守护线程
        captureThread.start();
    }

    /**
     * 关闭抓包句柄资源
     */
    private void closeCaptureHandle() {
        try {
            if (handle != null && handle.isOpen()) {
                handle.breakLoop();
                handle.close();
            }
        } catch (Exception e) {
            handleException(e);
        }
    }

    /**
     * 解析HTTP请求报文
     */
    private void parseHttpRequest(String payloadStr, PacketRecord.Builder builder) {
        String[] lines = payloadStr.split("\\r?\\n");
        if (lines.length == 0) return;

        String[] requestParts = lines[0].split(" ");
        if (requestParts.length >= 2) {
            builder.protocol("HTTP")
                    .protocolDetail(requestParts[0] + " " + requestParts[1]);
        }
    }

    /**
     * 解析HTTP响应报文
     */
    private void parseHttpResponse(String payloadStr, PacketRecord.Builder builder) {
        String[] lines = payloadStr.split("\\r?\\n");
        if (lines.length > 0) {
            builder.protocol("HTTP")
                    .protocolDetail(lines[0].substring(0, Math.min(lines[0].length(), 50)));
        }
    }

    /**
     * 抓包错误处理
     */
    private void handleCaptureError(Exception e) {
        if (isCapturing) {
            handleException(e);
        }
    }

    // endregion
}
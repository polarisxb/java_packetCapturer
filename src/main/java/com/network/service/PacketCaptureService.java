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
 * 数据包捕获服务核心类
 * 负责网络接口管理、抓包线程控制、数据解析和分发
 */
public class PacketCaptureService {
    // region 成员变量
    private PcapHandle handle;                   // Pcap4j抓包句柄
    private final NetworkAnalyzer analyzer = new NetworkAnalyzer(); // 数据分析器
    private volatile boolean isCapturing = false;// 抓包状态标志
    private NetworkInterfaceWrapper currentDevice; // 当前使用的网络设备
    private Thread captureThread;                // 抓包线程实例

    // 界面相关依赖
    private final PacketTableModel tableModel;    // 数据表格模型
    private final MainFrame mainFrame;           // 主界面引用

    // 性能优化参数
    private static final int MAX_BATCH_SIZE = 200;       // 批量处理最大包数
    private static final int BUFFER_FLUSH_INTERVAL = 500; // 最大刷新间隔(ms)
    private static final long MAX_BUFFER_TIME = 300;      // 缓冲时间窗口(ms)
    // endregion

    // region 构造函数
    /**
     * 构造抓包服务
     * @param tableModel 数据表格模型（用于更新界面）
     * @param mainFrame 主界面引用（用于状态更新）
     */
    public PacketCaptureService(PacketTableModel tableModel, MainFrame mainFrame) {
        this.tableModel = tableModel;
        this.mainFrame = mainFrame;
    }
    // endregion

    // region 公共方法
    /**
     * 获取数据分析器实例
     */
    public NetworkAnalyzer getAnalyzer() {
        return analyzer;
    }

    /**
     * 启动/恢复抓包
     * @param device 选择的网络接口设备
     */
    public void startCapture(NetworkInterfaceWrapper device) {
        try {
            // 设备变更或句柄不可用时重新初始化
            if (needReinitializeHandle(device)) {
                closeExistingHandle();
                initializeNewHandle(device);
            }

            // 确保单个抓包线程运行
            if (isCaptureThreadRunning()) {
                return;
            }

            // 启动抓包线程
            startCaptureThread();
        } catch (Exception e) {
            handleException(e);
        }
    }

    /**
     * 暂停抓包（保持网络接口打开）
     */
    public void pauseCapture() {
        isCapturing = false;
        mainFrame.updateStatus("抓包已暂停");
    }

    /**
     * 完全停止抓包（释放资源）
     */
    public void stopCapture() {
        isCapturing = false;
        closeCaptureHandle();
        mainFrame.updateStatus("抓包已停止");
    }

    /**
     * 获取当前抓包状态
     */
    public boolean isCapturing() {
        return isCapturing;
    }
    // endregion

    // region 核心抓包逻辑
    /**
     * 抓包主循环（在独立线程中运行）
     */
    private void captureLoop() {
        List<PacketRecord> buffer = new ArrayList<>(MAX_BATCH_SIZE);
        long lastFlushTime = System.currentTimeMillis();

        while (isCapturing) {
            try {
                Packet packet = handle.getNextPacketEx();
                if (packet == null) continue;

                // 解析并处理数据包
                processPacket(packet, buffer);

                // 判断是否需要刷新缓冲区
                if (shouldFlushBuffer(buffer, lastFlushTime)) {
                    flushBuffer(buffer);
                    lastFlushTime = System.currentTimeMillis();
                }
            } catch (Exception e) {
                handleCaptureError(e);
            }
        }

        // 循环结束后强制刷新剩余数据
        flushBuffer(buffer);
    }

    /**
     * 处理单个数据包
     */
    private void processPacket(Packet packet, List<PacketRecord> buffer) {
        PacketRecord record = parsePacket(packet);
        analyzer.analyze(record);
        buffer.add(record);
    }
    // endregion

    // region 数据包解析
    /**
     * 解析原始数据包为业务对象
     * @param packet 原始网络数据包
     * @return 格式化后的业务对象
     */
    private PacketRecord parsePacket(Packet packet) {
        PacketRecord.Builder builder = new PacketRecord.Builder(
                Instant.now(),
                packet.length(),
                packet
        );

        parseTransportLayer(packet, builder);
        parseNetworkLayer(packet, builder);

        return builder.build();
    }

    /**
     * 解析传输层协议（TCP/UDP）
     */
    private void parseTransportLayer(Packet packet, PacketRecord.Builder builder) {
        // TCP协议处理
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            builder.srcPort(tcp.getHeader().getSrcPort().value())
                    .dstPort(tcp.getHeader().getDstPort().value())
                    .protocol("TCP");

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
     */
    private void parseHttpPayload(TcpPacket tcp, PacketRecord.Builder builder) {
        if (tcp.getPayload() == null) return;

        byte[] payload = tcp.getPayload().getRawData();
        if (payload == null || payload.length == 0) return;

        try {
            String payloadStr = new String(payload, StandardCharsets.US_ASCII).trim();

            // 检测HTTP请求方法
            if (payloadStr.startsWith("GET") || payloadStr.startsWith("POST") ||
                    payloadStr.startsWith("PUT") || payloadStr.startsWith("DELETE")) {
                parseHttpRequest(payloadStr, builder);
            }
            // 检测HTTP响应
            else if (payloadStr.startsWith("HTTP/")) {
                parseHttpResponse(payloadStr, builder);
            }
        } catch (Exception e) {
            // 忽略非HTTP数据或解析错误
        }
    }
    // endregion

    // region 工具方法
    /**
     * 刷新缓冲区到界面
     */
    private void flushBuffer(List<PacketRecord> buffer) {
        if (buffer.isEmpty()) return;

        List<PacketRecord> copy = new ArrayList<>(buffer);
        buffer.clear();

        SwingUtilities.invokeLater(() -> {
            tableModel.addPackets(copy);
            mainFrame.updateStatus("已捕获: " + tableModel.getRowCount() + " 个包");
        });
    }

    /**
     * 判断是否需要刷新缓冲区
     */
    private boolean shouldFlushBuffer(List<PacketRecord> buffer, long lastFlushTime) {
        return buffer.size() >= MAX_BATCH_SIZE ||
                (System.currentTimeMillis() - lastFlushTime) > MAX_BUFFER_TIME;
    }

    /**
     * 异常统一处理
     */
    private void handleException(Exception e) {
        mainFrame.updateStatus("捕获错误: " + e.getMessage());
    }
    // endregion

    // region 私有辅助方法
    private boolean needReinitializeHandle(NetworkInterfaceWrapper device) {
        return handle == null ||
                !handle.isOpen() ||
                currentDevice == null ||
                !currentDevice.equals(device);
    }

    private void closeExistingHandle() throws NotOpenException {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    private void initializeNewHandle(NetworkInterfaceWrapper device) throws PcapNativeException {
        PcapNetworkInterface nif = device.getPcapDevice();
        handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        currentDevice = device;
    }

    private boolean isCaptureThreadRunning() {
        return captureThread != null && captureThread.isAlive();
    }

    private void startCaptureThread() {
        isCapturing = true;
        captureThread = new Thread(this::captureLoop);
        captureThread.setDaemon(true); // 设置为守护线程
        captureThread.start();
    }

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

    private void parseHttpRequest(String payloadStr, PacketRecord.Builder builder) {
        String[] lines = payloadStr.split("\\r?\\n");
        if (lines.length == 0) return;

        String[] requestParts = lines[0].split(" ");
        if (requestParts.length >= 2) {
            builder.protocol("HTTP")
                    .protocolDetail(requestParts[0] + " " + requestParts[1]);
        }
    }

    private void parseHttpResponse(String payloadStr, PacketRecord.Builder builder) {
        String[] lines = payloadStr.split("\\r?\\n");
        if (lines.length > 0) {
            builder.protocol("HTTP")
                    .protocolDetail(lines[0].substring(0, Math.min(lines[0].length(), 50)));
        }
    }

    private void handleCaptureError(Exception e) {
        if (isCapturing) {
            handleException(e);
        }
    }
    // endregion
}
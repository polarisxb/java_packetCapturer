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


public class PacketCaptureService {
    private PcapHandle handle;
    private final NetworkAnalyzer analyzer = new NetworkAnalyzer();
    private volatile boolean isCapturing = false;
    private final PacketTableModel tableModel;
    private final MainFrame mainFrame;
    private static final int BUFFER_FLUSH_INTERVAL = 500; // 最大刷新间隔500ms
    private static final int MAX_BATCH_SIZE = 200; // 增大批处理量
    private static final long MAX_BUFFER_TIME = 300; // 最大缓冲时间300ms

    // 添加正确的构造函数
    public PacketCaptureService(PacketTableModel tableModel, MainFrame mainFrame) {
        this.tableModel = tableModel;
        this.mainFrame = mainFrame;
    }
    public NetworkAnalyzer getAnalyzer() {
        return analyzer;
    }

    public void startCapture(NetworkInterfaceWrapper device) {
        try {
            PcapNetworkInterface nif = device.getPcapDevice();
            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);

            isCapturing = true;
            new Thread(this::captureLoop).start();

        } catch (PcapNativeException e) {
            handleException(e);
        }
    }
    private void flushBuffer(List<PacketRecord> buffer) {
        if (!buffer.isEmpty()) {
            List<PacketRecord> copy = new ArrayList<>(buffer);
            buffer.clear();
            SwingUtilities.invokeLater(() -> {
                tableModel.addPackets(copy);
                mainFrame.updateStatus("已捕获: " + tableModel.getRowCount() + " 个包");
            });
        }
    }

    private void captureLoop() {
        List<PacketRecord> buffer = new ArrayList<>(MAX_BATCH_SIZE);
        long lastFlushTime = System.currentTimeMillis();

        while (isCapturing) {
            try {
                Packet packet = handle.getNextPacketEx();
                if (packet == null) continue;
                PacketRecord record = parsePacket(packet);
                analyzer.analyze(record);
                buffer.add(record);

                // 双重缓冲条件
                boolean shouldFlush = buffer.size() >= MAX_BATCH_SIZE ||
                        System.currentTimeMillis() - lastFlushTime > MAX_BUFFER_TIME;

                if (shouldFlush) {
                    flushBuffer(buffer);
                    lastFlushTime = System.currentTimeMillis();
                }
            } catch (Exception e) {
                if (isCapturing) handleException(e);
            }
        }
        flushBuffer(buffer);
    }

    public void stopCapture() {
        isCapturing = false;
        try {
            if (handle != null) {
                if (handle.isOpen()) {
                    handle.breakLoop(); // 强制中断抓包循环
                    handle.close();
                }
            }
        } catch (NotOpenException e) {
            handleException(e);
        }
        mainFrame.updateStatus("抓包已停止");
    }

    private void handleException(Exception e) {
        mainFrame.updateStatus("捕获错误: " + e.getMessage());
    }
    private void parseHttpPayload(byte[] payload, PacketRecord.Builder builder) {
        try {
            String payloadStr = new String(payload, StandardCharsets.US_ASCII).trim();

            // 检测HTTP请求
            if (payloadStr.startsWith("GET") || payloadStr.startsWith("POST")
                    || payloadStr.startsWith("PUT") || payloadStr.startsWith("DELETE")) {
                String[] lines = payloadStr.split("\\r?\\n");
                if (lines.length > 0) {
                    String[] requestParts = lines[0].split(" ");
                    if (requestParts.length >= 2) {
                        builder.protocol("HTTP");
                        builder.protocolDetail(requestParts[0] + " " + requestParts[1]);
                    }
                }
            }
            // 检测HTTP响应
            else if (payloadStr.startsWith("HTTP/")) {
                String[] lines = payloadStr.split("\\r?\\n");
                if (lines.length > 0) {
                    builder.protocol("HTTP");
                    builder.protocolDetail(lines[0].substring(0, Math.min(lines[0].length(), 50)));
                }
            }
        } catch (Exception e) {
            // 非HTTP数据或解析失败时忽略
        }
    }
    private PacketRecord parsePacket(Packet packet) {
        PacketRecord.Builder builder = new PacketRecord.Builder(
                Instant.now(),
                packet.length(),
                packet
        );
        // 解析传输层
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            builder.srcPort(tcp.getHeader().getSrcPort().value())
                    .dstPort(tcp.getHeader().getDstPort().value())
                    .protocol("TCP");

            // 解析HTTP
            if (tcp.getPayload() != null) {
                byte[] payload = tcp.getPayload().getRawData();
                if (payload != null && payload.length > 0) {
                    parseHttpPayload(payload, builder);
                }
            }
        }
        else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            builder.srcPort(udp.getHeader().getSrcPort().value())
                    .dstPort(udp.getHeader().getDstPort().value())
                    .protocol("UDP");
        }
        if (packet.contains(IpPacket.class)) {
            IpPacket ip = packet.get(IpPacket.class);
            builder.srcIp(ip.getHeader().getSrcAddr().getHostAddress())
                    .dstIp(ip.getHeader().getDstAddr().getHostAddress())
                    .protocol(ip.getHeader().getProtocol().name());
        }

        return builder.build();
    }
}
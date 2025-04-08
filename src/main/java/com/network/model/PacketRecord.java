package com.network.model;

import org.pcap4j.packet.Packet;
import java.time.Instant;

/**
 * 网络数据包记录模型
 * 使用建造者模式(Builder Pattern)创建实例
 * 包含数据包解析后的所有关键信息
 */
public class PacketRecord {
    // region 成员变量
    private final Instant timestamp;     // 时间戳
    private final String srcIp;         // 源IP地址
    private final String dstIp;         // 目标IP地址
    private final String protocol;      // 协议类型（TCP/UDP/HTTP等）
    private final int length;           // 数据包长度（字节）
    private final Packet rawPacket;     // 原始数据包对象
    private final int srcPort;         // 源端口号（-1表示无效）
    private final int dstPort;         // 目标端口号（-1表示无效）
    private final String protocolDetail; // 协议详细信息（如HTTP方法）
    // endregion

    // region 建造者类
    /**
     * 建造者模式内部类
     * 提供链式调用构建PacketRecord对象
     */
    public static class Builder {
        // 必需参数
        private final Instant timestamp;
        private final int length;
        private final Packet rawPacket;

        // 可选参数（带默认值）
        private String srcIp = "N/A";
        private String dstIp = "N/A";
        private String protocol = "UNKNOWN";
        private int srcPort = -1;      // 默认无效端口
        private int dstPort = -1;      // 默认无效端口
        private String protocolDetail = "";

        /**
         * 建造者构造函数（必需参数）
         * @param timestamp 数据包时间戳
         * @param length 数据包长度
         * @param rawPacket 原始数据包对象
         */
        public Builder(Instant timestamp, int length, Packet rawPacket) {
            this.timestamp = timestamp;
            this.length = length;
            this.rawPacket = rawPacket;
        }

        // region 链式调用方法
        public Builder srcIp(String val) { srcIp = val; return this; }
        public Builder dstIp(String val) { dstIp = val; return this; }
        public Builder protocol(String val) { protocol = val; return this; }
        public Builder srcPort(int val) { srcPort = val; return this; }
        public Builder dstPort(int val) { dstPort = val; return this; }
        public Builder protocolDetail(String val) { protocolDetail = val; return this; }
        // endregion

        /**
         * 构建最终对象
         */
        public PacketRecord build() {
            return new PacketRecord(this);
        }
    }
    // endregion

    // region 构造函数
    /**
     * 全参数构造函数（建议通过Builder使用）
     */
    public PacketRecord(Instant timestamp, String srcIp, String dstIp,
                        String protocol, int length, Packet rawPacket,
                        int srcPort, int dstPort, String protocolDetail) {
        this.timestamp = timestamp;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.protocol = protocol;
        this.length = length;
        this.rawPacket = rawPacket;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocolDetail = protocolDetail;
    }

    /**
     * 私有构造函数（仅供Builder类使用）
     */
    private PacketRecord(Builder builder) {
        this.timestamp = builder.timestamp;
        this.srcIp = builder.srcIp;
        this.dstIp = builder.dstIp;
        this.protocol = builder.protocol;
        this.length = builder.length;
        this.rawPacket = builder.rawPacket;
        this.srcPort = builder.srcPort;
        this.dstPort = builder.dstPort;
        this.protocolDetail = builder.protocolDetail;
    }
    // endregion

    // region Getter方法
    public Instant getTimestamp() { return timestamp; }
    public String getSrcIp() { return srcIp; }
    public String getDstIp() { return dstIp; }
    public String getProtocol() { return protocol; }
    public int getLength() { return length; }
    public Packet getRawPacket() { return rawPacket; }
    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public String getProtocolDetail() { return protocolDetail; }
    // endregion
}
package com.network.model;
//M层，核心数据模型
import org.pcap4j.packet.Packet;

import java.time.Instant;

// model/PacketRecord.java
public class PacketRecord {
    private final Instant timestamp;
    private final String srcIp; //源地址
    private final String dstIp; //目标地址
    private final String protocol;
    private final int length;
    private final Packet rawPacket; //原始数据
    private final int srcPort;
    private final int dstPort;
    private final String protocolDetail;

    public static class Builder {
        private final Instant timestamp;
        private String srcIp = "N/A";
        private String dstIp = "N/A";
        private String protocol = "UNKNOWN";
        private int length;
        private Packet rawPacket;
        private int srcPort = -1;
        private int dstPort = -1;
        private String protocolDetail = "";

        public Builder(Instant timestamp, int length, Packet rawPacket) {
            this.timestamp = timestamp;
            this.length = length;
            this.rawPacket = rawPacket;
        }
        public Builder srcIp(String val) { srcIp = val; return this; }
        public Builder dstIp(String val) { dstIp = val; return this; }
        public Builder protocol(String val) { protocol = val; return this; }
        public Builder srcPort(int val) { srcPort = val; return this; }
        public Builder dstPort(int val) { dstPort = val; return this; }
        public Builder protocolDetail(String val) { protocolDetail = val; return this; }

        public PacketRecord build() {
            return new PacketRecord(this);
        }
    }

    // 构造函数、getters 和 toString() 方法
    public PacketRecord(Instant timestamp, String srcIp, String dstIp,
                        String protocol, int length, Packet rawPacket,int srcPort, int dstPort, String protocolDetail) {
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
    // 私有构造函数
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
    public Instant getTimestamp() { return timestamp; }
    public String getSrcIp() { return srcIp; }
    public String getDstIp() { return dstIp; }
    public String getProtocol() { return protocol; }
    public int getLength() { return length; }
    public Packet getRawPacket() { return rawPacket; }
    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public String getProtocolDetail() { return protocolDetail; }
}

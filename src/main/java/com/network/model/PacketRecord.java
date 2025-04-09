package com.network.model;

import org.pcap4j.packet.Packet;
import java.time.Instant;

/**
 * 网络数据包记录模型
 * 使用建造者模式(Builder Pattern)创建不可变对象，封装数据包解析后的关键信息
 *
 * 主要功能：
 * 1. 提供标准化的网络数据包信息存储结构
 * 2. 支持灵活的可选参数构建
 * 3. 保持原始数据包的引用以便后续深度解析
 */
public class PacketRecord {

    // region ====================== 成员变量 ======================

    /**
     * 数据包捕获时间戳（UTC时间，不可变）
     */
    private final Instant timestamp;

    /**
     * 源IP地址（IPv4/IPv6格式字符串，N/A表示未解析到）
     */
    private final String srcIp;

    /**
     * 目标IP地址（格式同源IP）
     */
    private final String dstIp;

    /**
     * 协议类型（大写格式，如TCP/UDP/HTTP等，UNKNOWN表示未知协议）
     */
    private final String protocol;

    /**
     * 数据包总长度（单位：字节）
     */
    private final int length;

    /**
     * 原始数据包对象（可能为null，需进行空值检查）
     */
    private final Packet rawPacket;

    /**
     * 源端口号（-1表示端口无效或未解析到）
     */
    private final int srcPort;

    /**
     * 目标端口号（处理规则同源端口）
     */
    private final int dstPort;

    /**
     * 协议详细说明（如HTTP方法、DNS查询类型等，可为空字符串）
     */
    private final String protocolDetail;

    // endregion

    // region ====================== 建造者类 ======================

    /**
     * 建造者模式实现类
     * 提供链式调用接口构建完整PacketRecord对象
     *
     * 使用规范：
     * 1. 必须参数通过构造函数初始化
     * 2. 可选参数通过链式方法设置
     * 3. 最终通过build()方法创建不可变对象
     */
    public static class Builder {
        // 必需参数（通过构造函数初始化）
        private final Instant timestamp;
        private final int length;
        private final Packet rawPacket;

        // 可选参数（带默认值）
        private String srcIp = "N/A";
        private String dstIp = "N/A";
        private String protocol = "UNKNOWN";
        private int srcPort = -1;
        private int dstPort = -1;
        private String protocolDetail = "";

        /**
         * 构造建造者对象（必须参数）
         * @param timestamp 数据包捕获时间（不可为null）
         * @param length 有效载荷长度（需≥0）
         * @param rawPacket 原始数据包对象（允许为null）
         */
        public Builder(Instant timestamp, int length, Packet rawPacket) {
            this.timestamp = timestamp;
            this.length = length;
            this.rawPacket = rawPacket;
        }

        // region ============ 链式调用方法 ============

        /**
         * 设置源IP地址
         * @param val IP地址字符串（自动处理null值）
         * @return 当前建造者实例
         */
        public Builder srcIp(String val) {
            srcIp = (val != null) ? val : "N/A";
            return this;
        }

        /**
         * 设置目标IP地址
         * @param val IP地址字符串（处理规则同源IP）
         */
        public Builder dstIp(String val) {
            dstIp = (val != null) ? val : "N/A";
            return this;
        }

        /**
         * 设置协议类型
         * @param val 协议标识字符串（建议大写格式）
         */
        public Builder protocol(String val) {
            protocol = (val != null) ? val : "UNKNOWN";
            return this;
        }

        /**
         * 设置源端口号
         * @param val 有效端口范围：0-65535，非法值设为-1
         */
        public Builder srcPort(int val) {
            srcPort = isValidPort(val) ? val : -1;
            return this;
        }

        /**
         * 设置目标端口号
         * @param val 处理规则同源端口
         */
        public Builder dstPort(int val) {
            dstPort = isValidPort(val) ? val : -1;
            return this;
        }

        /**
         * 设置协议详细信息
         * @param val 描述字符串（允许为空）
         */
        public Builder protocolDetail(String val) {
            protocolDetail = (val != null) ? val : "";
            return this;
        }

        // endregion

        /**
         * 构建最终PacketRecord对象
         * @return 完全初始化的不可变对象
         */
        public PacketRecord build() {
            return new PacketRecord(this);
        }

        /**
         * 验证端口号有效性
         */
        private boolean isValidPort(int port) {
            return port >= 0 && port <= 65535;
        }
    }

    // endregion

    // region ====================== 构造函数 ======================

    /**
     * 全参数构造函数（推荐通过Builder使用）
     *
     * @param timestamp 时间戳（必须非null）
     * @param srcIp 源IP地址
     * @param dstIp 目标IP地址
     * @param protocol 协议类型
     * @param length 数据包长度
     * @param rawPacket 原始数据包
     * @param srcPort 源端口
     * @param dstPort 目标端口
     * @param protocolDetail 协议详情
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
     * 私有构造函数（仅供Builder类内部使用）
     * @param builder 完全初始化的建造者对象
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

    // region ====================== Getter方法 ======================

    /**
     * 获取数据包时间戳
     */
    public Instant getTimestamp() { return timestamp; }

    /**
     * 获取源IP地址（可能返回"N/A"）
     */
    public String getSrcIp() { return srcIp; }

    /**
     * 获取目标IP地址（处理规则同源IP）
     */
    public String getDstIp() { return dstIp; }

    /**
     * 获取协议类型（始终返回非null值）
     */
    public String getProtocol() { return protocol; }

    /**
     * 获取数据包长度（单位：字节）
     */
    public int getLength() { return length; }

    /**
     * 获取原始数据包对象（可能为null）
     */
    public Packet getRawPacket() { return rawPacket; }

    /**
     * 获取源端口号（-1表示无效）
     */
    public int getSrcPort() { return srcPort; }

    /**
     * 获取目标端口号（处理规则同源端口）
     */
    public int getDstPort() { return dstPort; }

    /**
     * 获取协议详细信息（可能为空字符串）
     */
    public String getProtocolDetail() { return protocolDetail; }

    // endregion
}
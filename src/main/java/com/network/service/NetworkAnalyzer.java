package com.network.service;

import com.network.model.PacketRecord;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 网络数据包分析服务
 * 提供线程安全的实时流量统计和分析功能
 *
 * 主要功能：
 * 1. 协议类型分布统计
 * 2. 目标端口流量统计
 * 3. 总流量累计统计
 *
 * 线程安全实现：
 * - 使用ConcurrentHashMap保证并发写入安全
 * - 使用AtomicLong保证原子操作
 * - 返回统计快照避免锁竞争
 */
public class NetworkAnalyzer {

    // region ====================== 成员变量 ======================

    /**
     * 协议分布统计表
     * Key: 协议名称（大写，如TCP/UDP）
     * Value: 原子计数器（记录该协议出现的次数）
     */
    private final Map<String, AtomicLong> protocolStats = new ConcurrentHashMap<>();

    /**
     * 端口流量统计表
     * Key: 有效目标端口号（0-65535）
     * Value: 原子计数器（记录该端口累计流量字节数）
     */
    private final Map<Integer, AtomicLong> portTraffic = new ConcurrentHashMap<>();

    /**
     * 总流量统计器
     * 记录所有处理数据包的字节数总和
     */
    private final AtomicLong totalBytes = new AtomicLong(0);

    // endregion

    // region ====================== 核心方法 ======================

    /**
     * 分析网络数据包并更新统计信息
     * @param record 待分析的数据包记录对象（不可为null）
     *
     * 方法逻辑：
     * 1. 更新协议出现次数
     * 2. 更新有效端口流量
     * 3. 累加总流量
     * 4. 输出调试信息（开发环境）
     */
    public void analyze(PacketRecord record) {
        // 协议类型统计（自动处理新协议类型的初始化）
        protocolStats.computeIfAbsent(
                record.getProtocol(),
                k -> new AtomicLong(0)
        ).incrementAndGet();

        // 端口流量统计（仅处理有效目标端口）
        int dstPort = record.getDstPort();
        if (dstPort != -1) {
            portTraffic.computeIfAbsent(
                    dstPort,
                    k -> new AtomicLong(0)
            ).addAndGet(record.getLength());
        }

        // 调试信息输出（生产环境应替换为SLF4J等日志框架）
        System.out.println("[DEBUG] 分析数据包: " + record.getProtocol()
                + " 长度: " + record.getLength());

        // 总流量累加（原子操作保证线程安全）
        totalBytes.addAndGet(record.getLength());
    }

    // endregion

    // region ====================== 统计访问方法 ======================

    /**
     * 获取当前协议分布快照
     * @return 不可修改的协议统计映射表
     *         Key: 协议名称
     *         Value: 出现次数
     *
     * 注意：返回的是瞬时状态，高并发场景可能与实时数据存在微小差异
     */
    public Map<String, Long> getProtocolDistribution() {
        return protocolStats.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(
                        Map.Entry::getKey,
                        e -> e.getValue().get()
                ));
    }

    /**
     * 获取当前端口流量快照
     * @return 不可修改的端口统计映射表
     *         Key: 有效目标端口号
     *         Value: 累计接收字节数
     *
     * 注意：仅包含有效端口（dstPort != -1）的统计结果
     */
    public Map<Integer, Long> getPortTraffic() {
        return portTraffic.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(
                        Map.Entry::getKey,
                        e -> e.getValue().get()
                ));
    }

    /**
     * 获取总流量统计值
     * @return 累计处理的网络字节总数
     *
     * 注意：返回long类型可能存在的数值溢出问题（约9223372036GB）
     */
    public long getTotalBytes() {
        return totalBytes.get();
    }

    // endregion
}
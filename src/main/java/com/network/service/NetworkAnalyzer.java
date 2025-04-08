package com.network.service;

import com.network.model.PacketRecord;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 网络数据包分析器
 * 负责协议分布统计、端口流量统计和总流量计算
 */
public class NetworkAnalyzer {
    // 协议统计（线程安全）：Key-协议名称，Value-出现次数
    private final Map<String, AtomicLong> protocolStats = new ConcurrentHashMap<>();

    // 端口流量统计（线程安全）：Key-目标端口，Value-累计字节数
    private final Map<Integer, AtomicLong> portTraffic = new ConcurrentHashMap<>();

    // 总流量统计（线程安全）
    private final AtomicLong totalBytes = new AtomicLong(0);

    /**
     * 分析数据包并更新统计信息
     * @param record 要分析的数据包记录
     */
    public void analyze(PacketRecord record) {
        // 协议出现次数统计（原子操作保证线程安全）
        protocolStats.computeIfAbsent(record.getProtocol(), k -> new AtomicLong(0))
                .incrementAndGet();

        // 端口流量统计（仅统计有效目标端口）
        if(record.getDstPort() != -1) {
            portTraffic.computeIfAbsent(record.getDstPort(), k -> new AtomicLong(0))
                    .addAndGet(record.getLength());
        }

        // 调试输出（生产环境建议使用日志框架）
        System.out.println("[DEBUG] 分析数据包: " + record.getProtocol()
                + " 长度: " + record.getLength());

        // 总流量累加（原子操作保证线程安全）
        totalBytes.addAndGet(record.getLength());
    }

    // region 统计结果获取方法

    /**
     * 获取协议分布统计（返回不可修改的快照）
     * @return Key-协议名称，Value-出现次数
     */
    public Map<String, Long> getProtocolDistribution() {
        return protocolStats.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
    }

    /**
     * 获取端口流量统计（返回不可修改的快照）
     * @return Key-目标端口，Value-累计字节数
     */
    public Map<Integer, Long> getPortTraffic() {
        return portTraffic.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
    }

    /**
     * 获取总流量字节数
     * @return 累计处理的网络字节总数
     */
    public long getTotalBytes() {
        return totalBytes.get();
    }
    // endregion
}
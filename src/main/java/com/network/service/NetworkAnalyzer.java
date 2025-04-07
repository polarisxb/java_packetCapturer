package com.network.service;

import com.network.model.PacketRecord;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class NetworkAnalyzer {
    private final Map<String, AtomicLong> protocolStats = new ConcurrentHashMap<>();
    private final Map<Integer, AtomicLong> portTraffic = new ConcurrentHashMap<>();
    private final AtomicLong totalBytes = new AtomicLong(0);

    public void analyze(PacketRecord record) {
        // 协议统计
        protocolStats.computeIfAbsent(record.getProtocol(), k -> new AtomicLong(0))
                .incrementAndGet();

        // 端口流量统计
        if(record.getDstPort() != -1) {
            portTraffic.computeIfAbsent(record.getDstPort(), k -> new AtomicLong(0))
                    .addAndGet(record.getLength());
        }
        System.out.println("[DEBUG] 分析数据包: " + record.getProtocol()
                + " 长度: " + record.getLength());
        // 总流量统计
        totalBytes.addAndGet(record.getLength());

    }

    // 获取统计结果
    public Map<String, Long> getProtocolDistribution() {
        return protocolStats.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
    }

    public Map<Integer, Long> getPortTraffic() {
        return portTraffic.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
    }

    public long getTotalBytes() {
        return totalBytes.get();
    }
}
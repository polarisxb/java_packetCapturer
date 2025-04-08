package com.network.model;

import org.pcap4j.core.PcapNetworkInterface;
import java.net.Inet4Address;
import java.util.Optional;

/**
 * 网络接口设备包装类
 * 封装Pcap4j原始网络接口对象，提供格式化输出
 */
public class NetworkInterfaceWrapper {
    // region 成员变量
    private final PcapNetworkInterface device; // 原始设备对象
    // endregion

    // region 构造函数
    /**
     * 构造网络接口包装对象
     * @param device Pcap4j原始网络接口对象
     */
    public NetworkInterfaceWrapper(PcapNetworkInterface device) {
        this.device = device;
    }
    // endregion

    // region 公共方法
    /**
     * 获取原始设备对象
     */
    public PcapNetworkInterface getPcapDevice() {
        return device;
    }

    /**
     * 生成设备详细信息字符串
     * @return 格式：设备名 | IP: xxx | MAC: xxx | Desc: xxx
     */
    @Override
    public String toString() {
        if (device == null) return "No Device Available";

        StringBuilder sb = new StringBuilder();
        // 基础信息
        sb.append(device.getName()).append(" | ");

        // IPv4地址处理
        appendIPv4Info(sb);
        // MAC地址处理
        appendMACInfo(sb);
        // 描述信息处理
        appendDescription(sb);

        return sb.toString();
    }
    // endregion

    // region 私有方法
    /**
     * 添加IPv4地址信息
     */
    private void appendIPv4Info(StringBuilder sb) {
        String ipv4 = device.getAddresses().stream()
                .filter(a -> a.getAddress() instanceof Inet4Address)
                .findFirst()
                .map(a -> a.getAddress().getHostAddress())
                .orElse("No IPv4");
        sb.append("IP: ").append(ipv4).append(" | ");
    }

    /**
     * 添加MAC地址信息
     */
    private void appendMACInfo(StringBuilder sb) {
        String mac = Optional.ofNullable(device.getLinkLayerAddresses())
                .filter(list -> !list.isEmpty())
                .map(list -> {
                    byte[] macBytes = list.get(0).getAddress();
                    return formatMac(macBytes);
                })
                .orElse("No MAC");
        sb.append("MAC: ").append(mac);
    }

    /**
     * 添加描述信息
     */
    private void appendDescription(StringBuilder sb) {
        if (device.getDescription() != null) {
            sb.append(" | Desc: ").append(device.getDescription());
        }
    }

    /**
     * 格式化MAC地址为十六进制字符串
     * @param mac MAC地址字节数组
     * @return 格式：XX:XX:XX:XX:XX:XX
     */
    private static String formatMac(byte[] mac) {
        if (mac == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X", mac[i]));
            if (i < mac.length - 1) sb.append(":");
        }
        return sb.toString();
    }
    // endregion
}
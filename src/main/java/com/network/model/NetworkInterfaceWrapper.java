package com.network.model;

import org.pcap4j.core.PcapNetworkInterface;
import java.net.Inet4Address;
import java.util.Optional;

/**
 * 网络接口设备包装类
 * 封装Pcap4j原始网络接口对象，提供格式化输出和便捷访问方法
 *
 * 主要功能：
 * 1. 解耦业务代码与底层库的直接依赖
 * 2. 标准化网络接口信息展示格式
 * 3. 处理底层库可能返回的空值情况
 */
public class NetworkInterfaceWrapper {

    // region ====================== 成员变量 ======================

    /**
     * 原始网络接口对象（来自Pcap4j库）
     * 不可变对象，通过构造函数初始化
     */
    private final PcapNetworkInterface device;

    // endregion

    // region ====================== 构造函数 ======================

    /**
     * 构造网络接口包装对象
     * @param device Pcap4j库提供的原始网络接口对象
     *              允许为null，但会导致toString()返回"无设备"
     */
    public NetworkInterfaceWrapper(PcapNetworkInterface device) {
        this.device = device;
    }

    // endregion

    // region ====================== 公共方法 ======================

    /**
     * 获取原始设备对象
     * @return 可能为null的原始设备对象，调用方需处理空值情况
     */
    public PcapNetworkInterface getPcapDevice() {
        return device;
    }

    /**
     * 生成标准化的设备信息字符串
     * @return 格式："设备名 | IP: xxx | MAC: xxx | Desc: xxx"
     *         设备名为Pcap4j的原始名称
     *         IP地址优先显示IPv4地址，无则显示"No IPv4"
     *         MAC地址无则显示"No MAC"
     *         描述信息不存在时不显示Desc部分
     */
    @Override
    public String toString() {
        if (device == null) return "No Device Available";

        StringBuilder sb = new StringBuilder();
        // 设备基础信息
        sb.append(device.getName()).append(" | ");

        // 网络层信息处理
        appendIPv4Info(sb);
        // 数据链路层信息处理
        appendMACInfo(sb);
        // 可选描述信息处理
        appendDescription(sb);

        return sb.toString();
    }

    // endregion

    // region ====================== 私有方法 ======================

    /**
     * 提取并添加IPv4地址信息
     * @param sb 目标字符串构建器，方法执行后会追加IP信息
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
     * 提取并添加MAC地址信息
     * @param sb 目标字符串构建器，方法执行后会追加MAC信息
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
     * 添加可选的设备描述信息
     * @param sb 目标字符串构建器，仅在描述存在时追加信息
     */
    private void appendDescription(StringBuilder sb) {
        if (device.getDescription() != null) {
            sb.append(" | Desc: ").append(device.getDescription());
        }
    }

    /**
     * MAC地址字节数组转标准格式字符串
     * @param mac MAC地址字节数组（通常为6字节）
     * @return 十六进制表示的MAC地址，格式："XX:XX:XX:XX:XX:XX"
     *         输入为空时返回空字符串
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
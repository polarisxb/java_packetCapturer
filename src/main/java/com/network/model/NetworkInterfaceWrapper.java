package com.network.model;
//模型层

import org.pcap4j.core.PcapNetworkInterface;

import java.net.Inet4Address;
import java.util.Optional;

public class NetworkInterfaceWrapper {
    private final PcapNetworkInterface device;

    public NetworkInterfaceWrapper(PcapNetworkInterface device) {
        this.device = device;
    }
    public PcapNetworkInterface getPcapDevice() {
        return device;
    }

    // 增加详细信息的构造方法
    @Override
    public String toString() {
        if (device == null) return "No Device Available";

        StringBuilder sb = new StringBuilder();
        sb.append(device.getName()).append(" | ");

        // 获取IPv4地址
        String ipv4 = device.getAddresses().stream()
                .filter(a -> a.getAddress() instanceof Inet4Address)
                .findFirst()
                .map(a -> a.getAddress().getHostAddress())
                .orElse("No IPv4");
        sb.append("IP: ").append(ipv4).append(" | ");

        // 获取MAC地址
        String mac = Optional.ofNullable(device.getLinkLayerAddresses())
                .filter(list -> !list.isEmpty())
                .map(list -> {
                    byte[] macBytes = list.get(0).getAddress();
                    return formatMac(macBytes);
                })
                .orElse("No MAC");
        sb.append("MAC: ").append(mac);

        // 添加描述信息（如果有）
        if (device.getDescription() != null) {
            sb.append(" | Desc: ").append(device.getDescription());
        }

        return sb.toString();
    }

    private static String formatMac(byte[] mac) {//对mac地址进行的格式化
        if (mac == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X", mac[i]));
            if (i < mac.length - 1) sb.append(":");
        }
        return sb.toString();
    }
}
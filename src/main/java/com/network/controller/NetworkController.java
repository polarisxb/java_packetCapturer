package com.network.controller;

import com.network.model.NetworkInterfaceWrapper;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 网络设备控制器
 * 负责枚举和管理本地网络接口设备
 */
public class NetworkController {

    // region 公共方法

    /**
     * 获取可用网络设备列表
     * @return 封装后的网络接口设备集合（可能为空）
     * @implNote 使用Pcap4j库实现底层设备发现
     */
    public List<NetworkInterfaceWrapper> getAvailableDevices() {
        List<NetworkInterfaceWrapper> devices = new ArrayList<>();

        try {
            // 调用Pcap4j原生API获取网络接口
            for (PcapNetworkInterface device : Pcaps.findAllDevs()) {
                // 将原始设备对象封装为自定义包装对象
                devices.add(new NetworkInterfaceWrapper(device));
            }
        } catch (Exception e) {
            // 用户友好的错误提示（避免静默失败）
            JOptionPane.showMessageDialog(null,
                    "设备枚举失败: " + e.getMessage(),
                    "错误",
                    JOptionPane.ERROR_MESSAGE);
        }

        return devices;
    }
    // endregion
}
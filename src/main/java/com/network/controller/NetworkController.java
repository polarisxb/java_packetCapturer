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
 *
 * 使用Pcap4j库实现底层网络接口操作，提供设备列表的封装和异常处理
 */
public class NetworkController {

    // region ====================== 公共方法 ======================

    /**
     * 获取当前系统所有可用的网络接口设备
     * @return 封装后的网络接口设备集合（可能为空集合，但不会为null）
     * @implNote 底层使用Pcap4j库的Pcaps.findAllDevs()方法进行设备发现
     * @implWarning 当没有权限访问网络接口时可能返回空列表
     */
    public List<NetworkInterfaceWrapper> getAvailableDevices() {
        List<NetworkInterfaceWrapper> devices = new ArrayList<>();

        try {
            // 使用Pcap4j库发现所有网络接口设备
            List<PcapNetworkInterface> rawDevices = Pcaps.findAllDevs();

            // 将原始设备对象封装为自定义包装对象，解耦业务逻辑与底层实现
            for (PcapNetworkInterface device : rawDevices) {
                devices.add(new NetworkInterfaceWrapper(device));
            }

        } catch (Exception e) {
            // 用户友好的错误处理：显示GUI弹窗而非静默失败
            JOptionPane.showMessageDialog(
                    null,
                    "网络设备枚举失败: " + e.getMessage(),
                    "硬件访问错误",
                    JOptionPane.ERROR_MESSAGE
            );

            // 可选：在此添加日志记录（需日志框架支持）
            // logger.error("设备枚举异常", e);
        }

        return devices;
    }

    // endregion
}
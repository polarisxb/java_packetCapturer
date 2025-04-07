package com.network.controller;


import com.network.model.NetworkInterfaceWrapper;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class NetworkController {
    public List<NetworkInterfaceWrapper> getAvailableDevices() {
        List<NetworkInterfaceWrapper> devices = new ArrayList<>();
        try {
            //使用Pcap4j库获取所有网络接口
            for (PcapNetworkInterface device : Pcaps.findAllDevs()) {
                // 将原始设备对象封装为自定义包装对象
                devices.add(new NetworkInterfaceWrapper(device));
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Error listing devices: " + e.getMessage());
        }
        return devices;
    }
}
package com.network.view;

import com.network.model.PacketRecord;
import com.network.view.MainFrame;
import javax.swing.table.AbstractTableModel;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * 数据包表格模型
 * 管理抓包结果的表格数据显示和更新
 */
public class PacketTableModel extends AbstractTableModel {
    // region 成员变量
    private final List<PacketRecord> data = new ArrayList<>(); // 数据存储
    private final String[] COLUMNS = {"时间", "源IP", "目的IP", "协议", "长度"}; // 列定义

    // 数据更新监听器列表
    private final List<DataUpdateListener> listeners = new ArrayList<>();
    // endregion

    // region 表格模型基本方法
    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }
    // endregion

    // region 数据更新接口
    /**
     * 数据更新监听器接口
     * 用于在数据添加时通知界面更新
     */
    public interface DataUpdateListener {
        void onDataAdded(int count);
    }

    /**
     * 添加数据更新监听器
     * @param listener 需要监听数据更新的对象
     */
    public void addDataUpdateListener(DataUpdateListener listener) {
        listeners.add(listener);
    }
    // endregion

    // region 数据操作方法
    /**
     * 添加单个数据包记录（线程安全）
     * @param record 要添加的数据包记录
     */
    public void addPacket(PacketRecord record) {
        synchronized(data) {
            int index = data.size();
            data.add(record);
            // 通知表格插入行
            fireTableRowsInserted(index, index);
        }
    }

    /**
     * 批量添加数据包记录（线程安全）
     * @param packets 要添加的数据包集合
     */
    public void addPackets(List<PacketRecord> packets) {
        synchronized(data) {
            int startIndex = data.size();
            data.addAll(packets);
            // 通知表格批量插入行
            fireTableRowsInserted(startIndex, data.size() - 1);
            // 触发监听器回调
            listeners.forEach(l -> l.onDataAdded(packets.size()));
        }
    }

    /**
     * 清空所有数据（线程安全）
     */
    public void clear() {
        int size = data.size();
        data.clear();
        // 通知表格删除行
        fireTableRowsDeleted(0, size-1);
    }
    // endregion

    // region 数据获取方法
    @Override
    public Object getValueAt(int row, int col) {
        PacketRecord r = data.get(row);
        return switch (col) {
            case 0 -> DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
                    .format(r.getTimestamp().atZone(ZoneId.systemDefault()));
            case 1 -> r.getSrcIp();
            case 2 -> r.getDstIp();
            case 3 -> r.getProtocol();
            case 4 -> r.getLength() + " B";
            default -> "";
        };
    }
    // endregion
}
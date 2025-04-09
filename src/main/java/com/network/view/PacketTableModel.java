package com.network.view;

import com.network.model.PacketRecord;
import javax.swing.table.AbstractTableModel;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * 数据包表格模型
 * 管理抓包结果的表格数据显示和更新，提供以下功能：
 * 1. 线程安全的数据存储和访问
 * 2. 表格数据变更通知
 * 3. 批量数据更新优化
 * 4. 时间格式标准化
 */
public class PacketTableModel extends AbstractTableModel {

    // region ====================== 成员变量 ======================

    /**
     * 数据存储集合（使用synchronized保证线程安全）
     */
    private final List<PacketRecord> data = new ArrayList<>();

    /**
     * 表格列定义（顺序必须与getValueAt的case顺序一致）
     */
    private final String[] COLUMNS = {"时间", "源IP", "目的IP", "协议", "长度"};

    /**
     * 数据更新监听器列表（使用CopyOnWriteArrayList更安全，当前版本保持原有实现）
     */
    private final List<DataUpdateListener> listeners = new ArrayList<>();

    // endregion

    // region ====================== 表格模型基本方法 ======================

    /**
     * 获取表格行数
     * @return 当前存储的数据包记录数量
     */
    @Override
    public int getRowCount() {
        return data.size();
    }

    /**
     * 获取表格列数
     * @return 固定5列
     */
    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    /**
     * 获取列名称
     * @param column 列索引（0-4）
     * @return 列标题字符串
     */
    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    // endregion

    // region ====================== 数据更新监听接口 ======================

    /**
     * 数据更新监听器接口
     * 用于在数据发生变更时通知关联组件
     */
    public interface DataUpdateListener {
        /**
         * 数据添加事件回调
         * @param count 本次添加的记录数量
         */
        void onDataAdded(int count);
    }

    /**
     * 添加数据更新监听器
     * @param listener 需要接收数据变更通知的对象
     */
    public void addDataUpdateListener(DataUpdateListener listener) {
        listeners.add(listener);
    }

    // endregion

    // region ====================== 数据操作方法 ======================

    /**
     * 添加单个数据包记录（线程安全）
     * @param record 要添加的数据包记录对象（不可为null）
     */
    public void addPacket(PacketRecord record) {
        synchronized(data) {
            int index = data.size();
            data.add(record);
            // 精确通知表格行插入，避免全表刷新
            fireTableRowsInserted(index, index);
        }
    }

    /**
     * 批量添加数据包记录（优化性能）
     * @param packets 要添加的数据包集合（可为空）
     */
    public void addPackets(List<PacketRecord> packets) {
        if (packets == null || packets.isEmpty()) return;

        synchronized(data) {
            int startIndex = data.size();
            data.addAll(packets);
            // 批量通知表格行范围插入
            fireTableRowsInserted(startIndex, data.size() - 1);
            // 触发监听器回调（需考虑监听器执行时间）
            listeners.forEach(l -> l.onDataAdded(packets.size()));
        }
    }

    /**
     * 清空所有数据（线程安全）
     */
    public void clear() {
        synchronized(data) {
            int size = data.size();
            if (size > 0) {
                data.clear();
                // 通知全表数据删除
                fireTableRowsDeleted(0, size-1);
            }
        }
    }

    // endregion

    // region ====================== 数据获取方法 ======================

    /**
     * 获取指定单元格的值
     * @param row 行索引（0-based）
     * @param col 列索引（0-4）
     * @return 格式化后的单元格数据
     */
    @Override
    public Object getValueAt(int row, int col) {
        PacketRecord r = data.get(row);
        return switch (col) {
            case 0 -> // 时间列：格式化为本地时区的HH:mm:ss.SSS
                    DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
                            .format(r.getTimestamp().atZone(ZoneId.systemDefault()));
            case 1 -> r.getSrcIp();    // 源IP地址
            case 2 -> r.getDstIp();    // 目标IP地址
            case 3 -> r.getProtocol(); // 协议类型
            case 4 -> r.getLength() + " B"; // 数据包长度（带单位）
            default -> "";
        };
    }

    // endregion

    // region ====================== 辅助方法 ======================

    /**
     * 获取指定行的原始数据记录
     * @param row 行索引
     * @return 数据包记录对象
     */
    public PacketRecord getPacketAt(int row) {
        return data.get(row);
    }

    // endregion
}
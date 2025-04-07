package com.network.view;

import com.network.model.PacketRecord;
import com.network.view.MainFrame;

import javax.swing.table.AbstractTableModel;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;


public class PacketTableModel extends AbstractTableModel {
    private final List<PacketRecord> data = new ArrayList<>();
    private final String[] COLUMNS = {"时间", "源IP", "目的IP", "协议", "长度"};
    private final List<DataUpdateListener> listeners = new ArrayList<>();
    @Override
    public int getRowCount() { return data.size(); }
    @Override
    public int getColumnCount() { return COLUMNS.length; }
    @Override
    public String getColumnName(int column) { return COLUMNS[column]; }
    public interface DataUpdateListener {
        void onDataAdded(int count);
    }
    public void addDataUpdateListener(DataUpdateListener listener) {
        listeners.add(listener);
    }
    public void addPacket(PacketRecord record) {
        synchronized(data) {
            int index = data.size();
            data.add(record);
            fireTableRowsInserted(index, index);
        }
    }
    public void addPackets(List<PacketRecord> packets) {
        synchronized(data) {
            int startIndex = data.size();
            data.addAll(packets);
            fireTableRowsInserted(startIndex, data.size() - 1);
            listeners.forEach(l -> l.onDataAdded(packets.size()));
        }
    }
    @Override
    public Object getValueAt(int row, int col) {  //
        PacketRecord r = data.get(row);
        return switch (col) {
            case 0 ->DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
                    .format(r.getTimestamp().atZone(ZoneId.systemDefault()));
            case 1 -> r.getSrcIp();
            case 2 -> r.getDstIp();
            case 3 -> r.getProtocol();
            case 4 -> r.getLength() + " B";
            default -> "";
        };
    }
    public void clear() {
        int size = data.size();
        data.clear();
        fireTableRowsDeleted(0, size-1);
    }
}
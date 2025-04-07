package com.example.networklogger;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.widget.Button;
import android.widget.Toast;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST_CODE = 1;
    private Button startButton;
    private Button stopButton;
    private Thread vpnThread;
    private volatile boolean running = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        startButton = findViewById(R.id.start_button);
        stopButton = findViewById(R.id.stop_button);

        startButton.setOnClickListener(v -> startVpn());
        stopButton.setOnClickListener(v -> stopVpn());
    }

    private void startVpn() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE);
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
        }
    }

    private void stopVpn() {
        running = false;
        Toast.makeText(this, "VPN Stopped", Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            Intent intent = new Intent(this, MyVpnService.class);
            startService(intent);
            Toast.makeText(this, "VPN Started", Toast.LENGTH_SHORT).show();
        }
    }

    public static class MyVpnService extends VpnService {
        private ParcelFileDescriptor vpnInterface;
        private Thread vpnThread;
        private volatile boolean running = false;

        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            if (running) return START_STICKY;
            running = true;
            vpnThread = new Thread(this::runVpn);
            vpnThread.start();
            return START_STICKY;
        }

        private void runVpn() {
            try {
                Builder builder = new Builder();
                builder.setSession("NetworkLogger");
                builder.addAddress("10.0.0.2", 32);
                builder.addRoute("0.0.0.0", 0);
                vpnInterface = builder.establish();

                FileOutputStream out = new FileOutputStream(
                    getExternalFilesDir(null) + "/network_log.pcap");
                
                writePcapHeader(out);

                ByteBuffer packet = ByteBuffer.allocate(65535);
                while (running) {
                    int length = vpnInterface.getFileDescriptor().read(packet.array());
                    if (length > 0) {
                        writePacket(out, packet.array(), length);
                        packet.clear();
                    }
                }
                out.close();
                vpnInterface.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void writePcapHeader(FileOutputStream out) throws IOException {
            byte[] header = new byte[] {
                (byte)0xd4, (byte)0xc3, (byte)0xb2, (byte)0xa1,
                0x02, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                (byte)0xff, (byte)0xff, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00
            };
            out.write(header);
        }

        private void writePacket(FileOutputStream out, byte[] data, int length) throws IOException {
            long timestamp = System.currentTimeMillis() / 1000;
            int tsSec = (int) timestamp;
            int tsUsec = (int) ((System.currentTimeMillis() % 1000) * 1000);

            out.write(intToBytes(tsSec));
            out.write(intToBytes(tsUsec));
            out.write(intToBytes(length));
            out.write(intToBytes(length));
            out.write(data, 0, length);
        }

        private byte[] intToBytes(int value) {
            return new byte[] {
                (byte) (value & 0xff),
                (byte) ((value >> 8) & 0xff),
                (byte) ((value >> 16) & 0xff),
                (byte) ((value >> 24) & 0xff)
            };
        }

        @Override
        public void onDestroy() {
            running = false;
            try {
                if (vpnInterface != null) vpnInterface.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            super.onDestroy();
        }
    }
}
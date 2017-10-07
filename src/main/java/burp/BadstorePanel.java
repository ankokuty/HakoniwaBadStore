package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.ItemEvent;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JToggleButton;

import badstore.BadStore;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpServer;

@SuppressWarnings("serial")
public class BadstorePanel extends JPanel implements IExtensionStateListener, Handler<AsyncResult<HttpServer>> {
	private JTextField textPort;
	JComboBox<String> comboHost;
	JToggleButton button;
	BadStore badstore;
	JLabel message;
	IBurpExtenderCallbacks callbacks;

	static String DEFAULT_HOST = "127.0.0.1";
	static int DEFAULT_PORT = 8528;

	/**
	 * Create the panel.
	 */
	public BadstorePanel(IBurpExtenderCallbacks callbacks) {
		super();
		this.callbacks = callbacks;
		JLabel labelPort = new JLabel("Port:");
		JLabel labelHost = new JLabel("Interface:");
		textPort = new JTextField(Integer.toString(DEFAULT_PORT), 5);
		comboHost = new JComboBox<String>();
		message = new JLabel("");
		message.setForeground(new Color(255, 153, 51));
		button = new JToggleButton("Stopped");
		LogTable table = new LogTable();

		String[] ipaddresses = new String[] { DEFAULT_HOST };
		try {
			Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
			List<String> list = new ArrayList<String>();
			List<String> list6 = new ArrayList<String>();
			list.add("0.0.0.0");
			list6.add("::");
			while (interfaces.hasMoreElements()) {
				NetworkInterface nic = interfaces.nextElement();
				Enumeration<InetAddress> addresses = nic.getInetAddresses();
				while (addresses.hasMoreElements()) {
					InetAddress address = addresses.nextElement();
					if (address instanceof Inet4Address) {
						list.add(address.getHostAddress());
					} else if (address instanceof Inet6Address) {
						list6.add(address.getHostAddress());
					}
				}
			}
			list.addAll(list6);
			ipaddresses = list.toArray(new String[] {});
		} catch (Exception ignore) {
		}

		for (int i = 0; i < ipaddresses.length; i++) {
			comboHost.addItem(ipaddresses[i]);
		}
		comboHost.setSelectedItem(DEFAULT_HOST);

		button.addItemListener(ev -> {
			message.setText("");
			if (ev.getStateChange() == ItemEvent.SELECTED) {
				try {
					int port = Integer.parseInt(textPort.getText());
					String host = (String) comboHost.getSelectedItem();

					disableComponents();
					new Thread(() -> {
						try {
							message.setText("Initializing data ... ");
							badstore = new BadStore(port, host, table);
							badstore.startServer(BadstorePanel.this);
							message.setText("");
						} catch (Exception e) {
							callbacks.printError(e.getMessage());
							throw new RuntimeException(e);
						}
					}).start();
				} catch (NumberFormatException e) {
					message.setText("Invalid port:");
					enableComponents();
				} catch (Exception e) {
					message.setText(e.getMessage());
					enableComponents();
				}

			} else if (ev.getStateChange() == ItemEvent.DESELECTED) {
				if (badstore != null) {
					badstore.stopServer();
				}
				enableComponents();
			}
		});

		JPanel panel = new JPanel();
		JScrollPane sp = new JScrollPane(table);

		panel.setLayout(new FlowLayout(FlowLayout.LEFT));
		panel.add(labelPort);
		panel.add(textPort);
		panel.add(labelHost);
		panel.add(comboHost);
		panel.add(button);
		panel.add(message);

		setLayout(new BorderLayout());
		add(panel, BorderLayout.PAGE_START);
		add(sp, BorderLayout.CENTER);
	}

	@Override
	public void handle(AsyncResult<HttpServer> event) {
		if (event.failed()) {
			badstore.stopServer();
			enableComponents();
			message.setText(event.cause().getMessage());
		}
	}

	private void disableComponents() {
		button.setText("Running");
		button.setSelected(true);
		textPort.setEnabled(false);
		comboHost.setEnabled(false);
	}

	private void enableComponents() {
		button.setText("Stopped");
		button.setSelected(false);
		textPort.setEnabled(true);
		comboHost.setEnabled(true);
	}

	@Override
	public void extensionUnloaded() {
		try {
			badstore.stopServer();
		} catch (Exception ignore) {
		}
	}
}

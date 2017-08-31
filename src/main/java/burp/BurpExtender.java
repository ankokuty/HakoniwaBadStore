package burp;

import java.awt.Component;

import javax.swing.SwingUtilities;

import badstore.BadStore;

public class BurpExtender implements IBurpExtender, ITab {
	private IBurpExtenderCallbacks callbacks;

	public static void main(String[] args) throws Exception {
		System.err.println("This is Burp Extension. Please load from Burp Suite.");
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName("Hakoniwa BadStore");

		SwingUtilities.invokeLater(() -> {
			callbacks.addSuiteTab(BurpExtender.this);
		});
		
		callbacks.printOutput("Hakoniwa BadStore is using " + BadStore.storeDir.getAbsolutePath() + " as a temporary directory.");
		callbacks.printOutput("If something goes wrong, delete this directory and restart the BadStore server.");
	}

	@Override
	public String getTabCaption() {
		return "BadStore";
	}

	@Override
	public Component getUiComponent() {
		BadstorePanel panel = new BadstorePanel(callbacks);
		callbacks.customizeUiComponent(panel);
		callbacks.registerExtensionStateListener(panel);
		return panel;
	}

}

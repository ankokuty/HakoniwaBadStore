package badstore;

public class StartBadStore {
	public static void main(String[] args) throws Exception {
		String host = "127.0.0.1";
		int port = 8528;

		Class.forName("org.sqlite.JDBC");

		try {
			if (args[0] != null) {
				host = args[0];
			}
		} catch (ArrayIndexOutOfBoundsException ignore) {
		}

		try {
			port = Integer.valueOf(args[1]);
		} catch (ArrayIndexOutOfBoundsException ignore) {
		} catch (NumberFormatException ignore) {
		}

		BadStore badstore = new BadStore(port, host, null);
		badstore.startServer(null);
	}
}

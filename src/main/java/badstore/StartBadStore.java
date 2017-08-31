package badstore;

public class StartBadStore {
	public static void main(String[] args) throws Exception {
		Class.forName("org.sqlite.JDBC");
		BadStore badstore = new BadStore(8528, "127.0.0.1", null);

		badstore.startServer(null);
	}
}

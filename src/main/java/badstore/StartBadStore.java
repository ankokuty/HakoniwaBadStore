package badstore;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;

public class StartBadStore {
	static SimpleDateFormat format = new SimpleDateFormat("dd/MM/yyyy:HH:mm:ss Z");
	static Pattern p = Pattern.compile("([\"\\\\])");

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

		BadStore badstore = new BadStore(port, host, context -> {
			HttpServerRequest request = context.request();
			HttpServerResponse response = context.response();

			response.endHandler(v -> {
				StringBuilder log = new StringBuilder();
				log.append(request.remoteAddress().host()).append(" ");
				log.append("- ");
				log.append("- ");
				log.append("[").append(format.format(new Date())).append("] ");
				p.matcher(request.rawMethod()).replaceAll("\\$0");
				log.append("\"").append(p.matcher(request.rawMethod()).replaceAll("\\\\$0")).append(" ");
				log.append(p.matcher(request.uri()).replaceAll("\\\\$0")).append(" ");
				switch (request.version()) {
				case HTTP_1_1:
					log.append("HTTP/1.1");
					break;
				default:
					log.append("HTTP/1.1");
				}
				log.append("\" ");
				log.append(Integer.toString(response.getStatusCode())).append(" ");
				log.append(response.bytesWritten());
				System.out.println(log.toString());
			});
			context.next();
		});
		badstore.startServer(null);
	}
}

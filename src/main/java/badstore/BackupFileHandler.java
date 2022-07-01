package badstore;

import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.impl.HttpUtils;
import io.vertx.core.net.impl.URIDecoder;
import io.vertx.ext.web.RoutingContext;

public class BackupFileHandler extends FileHandler {
	@Override
	public void handle(RoutingContext context) {
		String path = HttpUtils.removeDots(URIDecoder.decodeURIComponent(context.normalisedPath(), false));
		if (path == null) {
			context.fail(NOT_FOUND.code());
			return;
		}

		HttpServerResponse response = context.response();
		if (path.equals("/backup/")) {
			response.setChunked(true);
			if (BadStore.orderdb_bak.exists()) {
				response.write("orderdb.bak\n");
			}
			if (BadStore.userdb_bak.exists()) {
				response.write("userdb.bak\n");
			}
		} else {
			File file = null;
			if (path.equals("/backup/orderdb.bak")) {
				file = BadStore.orderdb_bak;
			} else if (path.equals("/backup/userdb.bak")) {
				file = BadStore.userdb_bak;
			}
			if (file == null || !file.exists()) {
				context.fail(NOT_FOUND.code());
				return;
			}

			InputStream is = null;
			try {
				is = new FileInputStream(file);
				output(context, is, "text/plain");
			} catch (FileNotFoundException e) {
				context.fail(NOT_FOUND.code());
				return;
			} finally {
				if (is != null) {
					try {
						is.close();
					} catch (IOException ignore) {
					}
				}
			}
		}
		response.end();
	}
}

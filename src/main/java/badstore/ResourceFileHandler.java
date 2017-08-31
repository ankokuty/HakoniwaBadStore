package badstore;

import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;

import java.io.IOException;
import java.io.InputStream;

import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.impl.MimeMapping;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.impl.Utils;

public class ResourceFileHandler implements Handler<RoutingContext> {
	@Override
	public void handle(RoutingContext context) {
		String path = Utils.removeDots(Utils.urlDecode(context.normalisedPath(), false));
		if (path == null) {
			context.fail(NOT_FOUND.code());
			return;
		}
		if (path.equals("/")) {
			path = "/index.html";
		}
		InputStream is = getClass().getResourceAsStream("htdocs" + path);
		if (is == null) {
			context.fail(NOT_FOUND.code());
			return;
		}

		try {
			HttpServerResponse response = context.response();
			String contentType = MimeMapping.getMimeTypeForFilename(path);
			response.putHeader("Content-Type", contentType != null ? contentType : "text/plain");
			int c = 0;
			Buffer buffer = Buffer.buffer();
			byte[] bytes = new byte[65536];
			while ((c = is.read(bytes)) != -1) {
				buffer.appendBytes(bytes, 0, c);
			}
			response.putHeader("Content-Length", Integer.toString(buffer.length()));
			response.write(buffer);
			response.end();
		} catch (IOException e) {
			context.fail(NOT_FOUND.code());
			return;
		}

	}
}

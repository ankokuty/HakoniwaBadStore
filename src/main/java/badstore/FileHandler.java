package badstore;

import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;

import java.io.IOException;
import java.io.InputStream;

import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

public abstract class FileHandler implements Handler<RoutingContext> {
	protected void output(RoutingContext context, InputStream is, String contentType) {
		try {
			HttpServerResponse response = context.response();
			response.putHeader("Content-Type", contentType != null ? contentType : "text/plain");
			int c = 0;
			Buffer buffer = Buffer.buffer();
			byte[] bytes = new byte[65536];
			while ((c = is.read(bytes)) != -1) {
				buffer.appendBytes(bytes, 0, c);
			}
			response.putHeader("Content-Length", Integer.toString(buffer.length()));
			response.write(buffer);
		} catch (IOException e) {
			context.fail(NOT_FOUND.code());
			return;
		}
	}
}

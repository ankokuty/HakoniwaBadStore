package badstore;

import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;

import java.io.InputStream;

import io.vertx.core.http.impl.MimeMapping;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.impl.Utils;

public class ResourceFileHandler extends FileHandler {
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
		String contentType = MimeMapping.getMimeTypeForFilename(path);
		output(context, is, contentType);
		context.response().end();
	}
}

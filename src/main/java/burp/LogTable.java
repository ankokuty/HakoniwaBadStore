package burp;

import java.util.Date;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

@SuppressWarnings("serial")
public class LogTable extends JTable implements Handler<RoutingContext> {
	DefaultTableModel model;
	final String[] columns = new String[] { "Time", "Method", "URL", "Status", "Length" };


	public LogTable() {
		model = new DefaultTableModel(columns, 0) {
		    @Override
		    public boolean isCellEditable(int row, int column) {
		       return false;
		    }
		};

		setModel(model);
	}

	@Override
	public void handle(RoutingContext context) {
		context.next();
		
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();
		
		model.addRow(new String[]{
			new Date().toString(),
			request.method().toString(),
			request.path(),
			Integer.toString(response.getStatusCode()),
			Long.toString(response.bytesWritten()),
		});
	}
}

package badstore;

import java.net.URLDecoder;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Date;

import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;

public class BSHeader extends CGI implements Handler<RoutingContext> {
	String price;
	String items;

	@Override
	public void handle(RoutingContext context) {
		HttpServerResponse response = context.response();
		response.setChunked(true);

		String action = context.request().getParam("action");
		if (action != null && action.equals("cartadd")) {
			cartadd(context);
		} else {
			/* Read CartID Cookie */
			Cookie ctemp = context.getCookie("CartID");
			items = null;
			float cost = 0;
			try {
				String[] c_cookievalue = URLDecoder.decode(ctemp.getValue(), "UTF-8").split(":");
				items = String.format(c_cookievalue[1]);
				cost = Float.parseFloat(c_cookievalue[2]);

			} catch (Exception ignore) {
			}
			price = "$" + String.format("%.2f", cost);
		}

		output(context);
	}

	private void cartadd(RoutingContext context) {
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();
		String sessid = Long.toString((new Date().getTime() / 1000));
		int cartitems = 0;
		float cartcost = 0;
		String cartitem = request.getParam("cartitem");

		if (cartitem == null || cartitem.equals("")) {
			String ipaddr = "";
			printHttpHeaders(response);
			response.write(start_html("BadStore.net - Cart Error"));
			response.write(header());
			response.write("<h1>Cart Error - Zero Items</h1>");
			response.write("<hr>");
			response.write("Something weird happened - you tried to add no items to the cart!");
			response.write("<p>");
			response.write("Use your browser's Back button and try again.");
			response.write("<p>");
			response.write("<p>");
			response.write("<p>");
			response.write("<h3>(If you're trying to hack - I know who you are:   " + ipaddr + ")</h3>");
			response.write(footer());
			response.write(end_html());
			response.end();
		} else {
			Connection connection = null;
			Statement statement = null;
			try {
				int _items = cartitems + 1;
				connection = DriverManager.getConnection("jdbc:sqlite:"+BadStore.dbfile.getAbsolutePath());
				statement = connection.createStatement();
				String sql = "SELECT price FROM itemdb WHERE itemnum = '" + cartitem + "'";
				ResultSet rs = statement.executeQuery(sql);
				if (!rs.next()) {
					throw new RuntimeException("Item number not found: ");
				} else {
					float cost = cartcost + rs.getFloat(1);
					// Create initial CartID cookie
					String cookievalue = String.join(":",
							new String[] { sessid, Integer.toString(_items), Float.toString(cost), cartitem });
					Cookie cartcookie = Cookie.cookie("CartID", url_encode(cookievalue));
					cartcookie.setPath("/");
					items = Integer.toString(_items);
					price = String.format("$%.2f", cost);
					context.addCookie(cartcookie);
				}
			} catch (SQLException e) {
				throw new RuntimeException(e);
			} finally {
				try {
					if (statement != null) {
						statement.close();
					}
				} catch (SQLException ignore) {
				}
				try {
					if (connection != null) {
						connection.close();
					}
				} catch (SQLException ignore) {
				}
			}
		}

	}

	private void output(RoutingContext context) {
		/* Read SSOid Cookie */
		Cookie stemp = context.getCookie("SSOid");
		String fullname = null;
		String role = null;
		try {
			String ssoid = new String(Base64.getDecoder().decode(stemp.getValue()));
			String[] s_cookievalue = ssoid.split(":");
			fullname = String.format(s_cookievalue[2]);
			role = s_cookievalue[3];
		} catch (Exception ignore) {
		}

		if (fullname == null || fullname.equals("")) {
			fullname = "{Unregistered User}";
		}
		if (items == null || items.equals("")) {
			items = "0";
		}

		HttpServerResponse response = context.response();
		response.putHeader("Content-type", "text/html");
		response.write(
				"<HTML><HEAD></HEAD><BODY><div style='margin-top: 7px; margin-left: 2px'><FONT FACE='Arial Narrow'>Welcome <B> "
						+ fullname + " </B> - Cart contains " + items + " items at " + price);
		if (role != null && role.equals("A")) {
			response.write(
					"<hr><font color=#004b2c><B>For Administrative Menu Options - <A TARGET='_top' HREF='/cgi-bin/badstore.cgi?action=admin'><i>Click Here</B><i></A></font>");
		}
		response.write("</div></BODY></HTML>\n");
		response.end();
	}

	static void printHttpHeaders(HttpServerResponse response) {
		response.putHeader("Content-Type", "text/html");
		response.putHeader("Server",
				"Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25");
		response.putHeader("ETag", "CPE1704TKS");
		response.putHeader("Cache-Control", "no-cache");
		response.putHeader("Pragma", "no-cache");
	}
}

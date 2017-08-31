package badstore;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;

public class BadStore extends CGI {
	int port;
	String host;
	HttpServer server;
	Handler<RoutingContext> logger;

	public static File storeDir;
	static File guestbookdb;
	static File rssfile;
	static File dbfile;

	static {
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException ignore) {
		}
		String tmpdir = System.getProperty("java.io.tmpdir");
		storeDir = new File(tmpdir, ".badstore/data");
		guestbookdb = new File(storeDir, "guestbookdb");
		rssfile = new File(storeDir, "rss.xml");
		dbfile = new File(storeDir, "badstore.db");
	}

	public BadStore(int port, String host, Handler<RoutingContext> logger) {
		super();

		this.port = port;
		this.host = host;
		this.logger = logger;

		System.setProperty("vertx.disableFileCaching", "true");
		if (!storeDir.exists()) {
			System.err.print("Initializing data ... ");
			new InitDBs().initialize();
			System.err.println("Done");
		}
	}

	public void startServer(Handler<AsyncResult<HttpServer>> error) {
		System.setProperty("vertx.cacheDirBase", storeDir.getAbsolutePath());
		Vertx vertx = Vertx.vertx();

		server = vertx.createHttpServer();

		Router router = Router.router(vertx);
		router.route().handler(logger);

		router.route().handler(CookieHandler.create());
		router.route(HttpMethod.GET, "/cgi-bin/badstore.cgi").handler(context -> {
			HttpServerResponse response = context.response();
			response.setChunked(true);
			String action = context.request().getParam("action");
			if (action != null) {
				switch (action) {
				case "whatsnew":
					whatsnew(context);
					break;
				case "qsearch":
					search(context);
					break;
				case "cartview":
					cartview(context);
					break;
				case "viewprevious":
					viewprevious(context);
					break;
				case "guestbook":
					guestbook(context);
					break;
				case "submitpayment":
					submitpayment(context);
					break;
				case "aboutus":
					aboutus(context);
					break;
				case "loginregister":
					loginregister(context);
					break;
				case "myaccount":
					myaccount(context);
					break;
				case "test":
					test(context);
					break;
				default:
					home(context);
				}
			} else {
				home(context);
			}
		});
		router.route(HttpMethod.POST, "/cgi-bin/badstore.cgi").handler(context -> {
			HttpServerResponse response = context.response();
			response.setChunked(true);

			String action = context.request().getParam("action");
			if (action != null) {
				switch (action) {
				case "cartadd":
					cartadd(context);
					break;
				case "order":
					order(context);
					break;
				case "submitpayment":
					submitpayment(context);
					break;
				case "doguestbook":
					doguestbook(context);
					break;
				case "login":
					authuser(context);
					break;
				case "register":
					authuser(context);
					break;
				case "moduser":
					moduser(context);
					break;
				default:
					home(context);
				}
			} else {
				home(context);
			}
		});

		router.route(HttpMethod.GET, "/cgi-bin/bsheader.cgi").handler(new BSHeader());
		router.route(HttpMethod.GET, "/cgi-bin/initdbs.cgi").handler(new InitDBs());
		router.route(HttpMethod.GET, "/rss.xml").handler(context -> {
			context.response().sendFile(rssfile.getAbsolutePath());
		});
		router.route("/*").handler(new ResourceFileHandler());
		server.requestHandler(router::accept).listen(port, host, error);
		System.err.println("Starting up badstore server on: http://" + host + ":" + port);
	}

	public void stopServer() {
		try {
			server.close();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/************
	 *** Home ***
	 ************/
	private void home(RoutingContext context) {
		HttpServerResponse response = context.response();
		response.setChunked(true);

		printHttpHeaders(response);
		response.write(header());
		response.write(start_html("Welcome to BadStore.net v2.1.1Beta - The most insecure store on the 'Net!"));
		response.write("<center><h1><font color=#004b2c>Welcome to BadStore.net!</font></h1>");
		response.write("<hr>");
		response.write("<p>");
		response.write("<img src=\"/images/store1.jpg\" border=\"0\">");
		response.write("</center>");
		response.write("<p>");
		response.write(footer());
		response.write(end_html());
		response.end();
	}

	/******************
	 *** What's New ***
	 ******************/
	public void whatsnew(RoutingContext context) {
		Connection connection = null;
		Statement statement = null;
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
			statement = connection.createStatement();
			String sql = "SELECT itemnum, sdesc, ldesc, price FROM itemdb WHERE isnew = 'Y'";
			ResultSet rs = statement.executeQuery(sql);

			HttpServerResponse response = context.response();
			response.setChunked(true);
			response.putHeader("Content-Type", "text/html");

			Map<String, String> ref = new HashMap<>();
			String url = "/cgi-bin/bsheader.cgi";
			ref.put("whatsnew_func", url);
			response.write(ajaxHeader(ref));
			response.write("<h1>The following are new items:</h1><TABLE BORDER=1>\n");
			response.write("<form>\n");

			response.write(
					"<Tr><th>ItemNum</th><th>Item</th><th>Description</th><th>Price</th><th>Image</th><th>Add to Cart</th></Tr>");

			while (rs.next()) {
				int itemnum = rs.getInt(1);
				String image = "/images/" + rs.getInt(1) + ".jpg";
				String nums = String.format("$%.2f", rs.getFloat(4));
				String sdesc = rs.getString(2);
				String ldesc = rs.getString(3);
				response.write("<tr><td>" + itemnum + "</td>");
				response.write("<td>" + sdesc + "</td>");
				response.write("<td>" + ldesc + "</td>");
				response.write("<td><div align=right>" + nums + "</div></td>");
				response.write("<td><div align=center><IMG SRC=" + image + "></div></td>");
				response.write(
						"<td><DIV id=\"radiobuttons\" align=center onclick=\"whatsnew_func(['action__cartadd', 'cartitem', 'NO_CACHE'], ['result'] );\"><input TYPE=\"checkbox\" ID=\"cartitem\" NAME=\"cartitems\" VALUE=\""
								+ itemnum + "\"></DIV></td></tr>\n");
			}

			response.write("</form>\n");
			response.write("</TABLE>\n");
			response.write("</div>\n");
			response.write(footer());
			response.write("</BODY>\n");
			response.write("</HTML>\n");
			response.end();
		} catch (Exception e) {
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

	/**************
	 *** Search ***
	 **************/
	public void search(RoutingContext context) {
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();

		String squery = request.getParam("searchquery");

		try {
			Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.parse(new FileInputStream(rssfile));
			document.getElementsByTagName("pubDate").item(0).setTextContent(getdate());
			document.getElementsByTagName("lastBuildDate").item(0).setTextContent(getdate());
			Node channel = document.getElementsByTagName("channel").item(0);
			NodeList items = document.getElementsByTagName("item");
			if (items.getLength() == 15) {
				Node lastItem = items.item(14);
				channel.removeChild(lastItem);
			}
			Node newItem = document.createElement("item");
			Node title = document.createElement("title");
			title.setTextContent("A Top Search Item at BadStore.net (BadStore.net)");
			Node link = document.createElement("link");
			link.setTextContent("http://www.badstore.net/cgi-bin/badstore.cgi?action=qsearch");
			Node guid = document.createElement("guid");
			guid.setTextContent("http://www.badstore.net/cgi-bin/badstore.cgi?action=&getdate");
			Node description = document.createElement("description");
			description.setTextContent(
					"<p><a href=\"http://www.badstore.net\"><img src=\"http://www.badstore.net/images/index.gif\" style=\"padding-left: 10px; padding-right: 10px; \" align=\"left\" alt=\"The Top Search Items at BadStore.net\" border=\"0\" /><a>BadStore.net Sales Operations Center - Here\'s what everybody else is looking for at BadStore.net!!!&nbsp If they all want it, you should too!<br><br><b>Search Item:</b>&nbsp "
							+ squery);
			newItem.appendChild(title);
			newItem.appendChild(link);
			newItem.appendChild(guid);
			newItem.appendChild(description);
			channel.insertBefore(newItem, items.item(0));

			TransformerFactory transFactory = TransformerFactory.newInstance();
			Transformer transformer = transFactory.newTransformer();

			FileOutputStream fos = new FileOutputStream(rssfile);
			StreamResult result = new StreamResult(fos);
			transformer.transform(new DOMSource(document), result);
			fos.close();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		/* Connect to the SQL Database */
		Connection connection = null;
		Statement statement = null;
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
			statement = connection.createStatement();
			if(!squery.matches("[0-9]+")) {
				squery = "'" + squery +"'";
			}
			String sql = "SELECT itemnum, sdesc, ldesc, price FROM itemdb WHERE " + squery
					+ " COLLATE nocase IN (itemnum,sdesc,ldesc)";
			ResultSet rs = statement.executeQuery(sql);

			printHttpHeaders(response);
			response.write(header());
			response.write(start_html("BadStore.net - Search Results"));
			response.write(comment("Search code developed by Bobby Jones - summer intern, 1996"));
			response.write(comment("Comment the $sql line out after troubleshooting is done"));

			if (!rs.next()) {
				response.write(h2("No items matched your search criteria: ") + sql);
			} else {
				response.write(h2("The following items matched your search criteria:"));
				response.write("<HR>");
				response.write(start_form("/cgi-bin/badstore.cgi?action=cartadd"));
				response.write("<TABLE BORDER=1>");
				response.write(tr(th("ItemNum") + th("Item") + th("Description") + th("Price") + th("Image")
						+ th("Add to Cart")));
				do {
					String image = "/images/" + rs.getInt(1) + ".jpg";
					response.write(tr(td(Integer.toString(rs.getInt(1))) + td(rs.getString(2)) + td(rs.getString(3))
							+ td(String.format("$%.2f", rs.getFloat(4)))
							+ td("align=\"CENTER\"", "<IMG SRC=" + image + ">") + td("align=\"CENTER\"",
									"<INPUT type=checkbox name=\"cartitem\" value=" + rs.getInt(1) + ">")));
				} while (rs.next());
				response.write("</TABLE>\n\n");
				response.write("<p>");
				response.write(submit("Add Items to Cart"));
				response.write("   ");
				response.write(reset());
				response.write("</Center>");
				response.write(end_form());
				response.write(footer());
				response.write(end_html());
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
		context.response().end();
	}

	/*********
	 * Admin *
	 *********/
	// TODO

	/****************
	 * Admin Portal *
	 ****************/
	// TODO

	/*************
	 * Guestbook *
	 *************/
	public void guestbook(RoutingContext context) {
		HttpServerResponse response = context.response();
		response.setChunked(true);

		printHttpHeaders(response);
		response.write(header());
		response.write(start_html("BadStore.net - Sign our Guestboo"));
		response.write(h1("Sign our Guestbook!"));
		response.write(hr());
		response.write(p());
		response.write(
				"Please complete this form to sign our Guestbook.  The email field is not required, but helps us contact you to respond to your feedback.  Thanks!");
		response.write(p());
		response.write(hr());
		response.write("<TABLE BORDER=0 CELLLPADDING=10>");
		response.write(start_form("/cgi-bin/badstore.cgi?action=doguestbook"));
		response.write(tr(td("Your Name:") + td("<INPUT TYPE=text NAME=name SIZE=30>")));
		response.write(tr(td("Email:") + td("<INPUT TYPE=text NAME=email SIZE=40>")));
		response.write(
				tr(td("valign=\"TOP\"", "Comments:") + td("<TEXTAREA NAME=comments COLS=60 ROWS=4></TEXTAREA>")));
		response.write("</TABLE>\n<HR>\n");
		response.write("<Center><INPUT TYPE=submit VALUE=\"Add Entry\">  <INPUT TYPE=reset></Center>");
		response.write(p());
		response.write(end_form());
		response.write(footer());
		response.write(end_html());
		response.end();
	}

	/****************
	 * Do Guestbook *
	 ****************/
	public void doguestbook(RoutingContext context) {
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();
		request.setExpectMultipart(true);
		request.endHandler(v -> {
			String timestamp = getdate();
			String name = request.getFormAttribute("name");
			String email = request.getFormAttribute("email");
			String comments = request.getFormAttribute("comments");
			if (comments != null) {
				comments = comments.trim();
			}

			saveFormData(guestbookdb, timestamp, name, email, comments);

			printHttpHeaders(response);
			response.write(header());
			response.write(start_html("Welcome to the BadStore.net Guestbook"));
			response.write(h1("Guestbook"));
			response.write(hr());

			response.write(readFormData(guestbookdb));

			response.write(footer());
			response.write(end_html());
			response.end();
		});
	}

	private void saveFormData(File dataFile, String timestamp, String name, String email, String comments) {
		PrintStream out = null;
		try {
			out = new PrintStream(new FileOutputStream(dataFile, true));
			out.print(timestamp + "~");
			out.print(name + "~");
			out.print(email + "~");
			out.println(comments);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (out != null) {
				out.close();
			}
		}
	}

	private String readFormData(File dataFile) {
		BufferedReader in = null;
		try {
			StringBuilder builder = new StringBuilder();
			in = new BufferedReader(new FileReader(dataFile));
			String line;
			while ((line = in.readLine()) != null) {
				String[] data = line.split("~");
				builder.append(data[0]);
				builder.append(": <B>");
				builder.append(data[1]);
				builder.append("</B> <A HREF=mailto:");
				builder.append(data[2]);
				builder.append(">");
				builder.append(data[2]);
				builder.append("</A>\n");
				builder.append("<OL><I>");
				builder.append(data[3]);
				builder.append("</I></OL>\n");
				builder.append("<HR>\n");
			}
			return builder.toString();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException ignore) {
				}
			}
		}
	}

	/*******************************
	 *** Get and format the date ***
	 *******************************/
	static String getdate() {
		SimpleDateFormat format = new SimpleDateFormat("EEEE, MMMM dd, yyyy 'at' HH:mm:ss");
		return format.format(new Date());
	}

	/***************
	 * Add to Cart *
	 ***************/
	public void cartadd(RoutingContext context) {
		HttpServerRequest request = context.request();
		request.setExpectMultipart(true);
		request.endHandler(v -> {
			String sessid = Long.toString((new Date().getTime() / 1000));
			int cartitems = 0;
			float cartcost = 0;
			String cartitem = request.getFormAttribute("cartitem");

			if (cartitem == null || cartitem.equals("")) {
				HttpServerResponse response = context.response();
				String ipaddr = "";
				printHttpHeaders(response);
				response.write(start_html("BadStore.net - Cart Error"));
				response.write(header());
				response.write(h1("Cart Error - Zero Items"));
				response.write("<hr>");
				response.write("Something weird happened - you tried to add no items to the cart!");
				response.write("<p>");
				response.write("Use your browser's Back button and try again.");
				response.write("<p>");
				response.write("<p>");
				response.write("<p>");
				response.write(h3("(If you're trying to hack - I know who you are:   " + ipaddr + ")"));
				response.write(footer());
				response.write(end_html());
				response.end();
			} else {
				Connection connection = null;
				Statement statement = null;
				try {
					int _items = cartitems + 1;
					connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
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
						Cookie cartcookie = Cookie.cookie("CartID", cookievalue);
						cartcookie.setPath("/");
						context.addCookie(cartcookie);
					}
				} catch (Exception e) {
					context.fail(e);
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

			home(context);
		});
	}

	/***************
	 * Place Order *
	 ***************/
	public void order(RoutingContext context) {
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();
		request.setExpectMultipart(true);
		request.endHandler(v -> {

			/* Read CartID Cookie */
			int items = 0;
			String cartitems = "";
			String price = "";
			String id = "";
			try {
				Cookie temp = context.getCookie("CartID");
				String[] cookievalue = URLDecoder.decode(temp.getValue(), "UTF-8").split(":");
				id = cookievalue[0];
				items = Integer.parseInt(cookievalue[1]);
				float cost = Float.parseFloat(cookievalue[2]);
				price = String.format("$%.2f", cost);
				String[] tmp_cartitems = new String[cookievalue.length - 3];
				System.arraycopy(cookievalue, 3, tmp_cartitems, 0, tmp_cartitems.length);
				cartitems = String.join(",", tmp_cartitems);
			} catch (Exception ignore) {
			}
			String email = request.getFormAttribute("email");
			String ipaddr = "";

			/* Expire the Cookie */
			Cookie cartcookie = Cookie.cookie("CartID", "");
			cartcookie.setMaxAge(0);
			cartcookie.setPath("/");
			context.addCookie(cartcookie);

			/* Get the hidden fields */
			String ccard = request.getFormAttribute("ccard");
			String expdate = request.getFormAttribute("expdate");

			printHttpHeaders(response);
			response.write(header());
			response.write(start_html("BadStore.net - Place Order"));
			response.write(h1("Your Order Has Been Placed") + "<hr><p>");

			/* Check for Empty Cart */
			if (items < 1) {
				response.write(h2("You have no items in your cart.") + "<p>");
				response.write("Order something already!<p>");
			} else {
				/* Connect to the SQL Database */
				Connection connection = null;
				Statement statement = null;
				try {
					connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
					statement = connection.createStatement();

					/* Add ordered items to Order Database */
					statement.executeUpdate(
							"INSERT INTO orderdb (sessid, orderdate, ordertime, ordercost, orderitems, itemlist, accountid, ipaddr, cartpaid, ccard, expdate) VALUES ('"
									+ id + "', DATE(), TIME(), '" + price + "', '" + items + "', '" + cartitems + "', '"
									+ email + "', '" + ipaddr + "', 'Y', '" + ccard + "', '" + expdate + "')");

					response.write(h2("You have just bought the following:") + "<p>");

					/* Prepare and Execute SQL Query */
					ResultSet rs = statement.executeQuery(
							"SELECT itemnum, sdesc, ldesc, price FROM itemdb WHERE itemnum IN (" + cartitems + ")");
					if (!rs.next()) {
						throw new RuntimeException("Item number not found:");
					} else {
						/* Read the matching records and print them out */
						response.write("<TABLE BORDER=1>");
						response.write(tr(th("ItemNum") + th("Item") + th("Description") + th("Price") + th("Image")));
						do {
							String image = "/images/" + rs.getInt(1) + ".jpg";
							response.write(tr(td(Integer.toString(rs.getInt(1))) + td(rs.getString(2))
									+ td(rs.getString(3)) + td(String.format("$%.2f", rs.getFloat(4)))
									+ td("align=\"CENTER\"", "<IMG SRC=" + image + ">")));
						} while (rs.next());
						response.write("</TABLE>\n\n" + "<p>");
						response.write(h3("Purchased:   " + items + " items at " + price) + "<p>");
						response.write("<Center><i>Thank you for shopping at BadStore.net!</i></Center>");
					}
					response.write(footer());
					response.write(end_html());
				} catch (Exception e) {
					context.fail(e);
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
			response.end();
		});
	}

	/******************
	 * Submit Payment *
	 ******************/
	public void submitpayment(RoutingContext context) {
		HttpServerRequest request = context.request();
		request.setExpectMultipart(true);
		request.endHandler(v -> {

			/* Read SSOid Cookie */
			Cookie stemp = context.getCookie("SSOid");
			String email = null;
			try {
				String ssoid = new String(Base64.getDecoder().decode(stemp.getValue()));
				String[] s_cookievalue = ssoid.split(":");
				email = String.format(s_cookievalue[0]);
			} catch (Exception ignore) {
			}

			String femail = "";
			if (email == null || email.equals("")) {
				femail = "Email Address: <INPUT TYPE=\"text\" NAME=\"email\"  SIZE=15 MAXLENGTH=40><p>";
			} else {
				femail = "Welcome, <b>" + email + "</b>" + hidden("email", email) + p();
			}

			String fname = request.getParam("fname");
			if (fname != null && fname.equals("shipsearch")) {
				checkship(context);
			} else if (fname != null && fname.equals("shipcost")) {
				doshipcost(context);
			} else {
				Show_Form(context, femail);
			}
		});
	}

	private void checkship(RoutingContext context) {
		HttpServerRequest request = context.request();
		String searchterm = request.getParam("args");

		String sql = "select country from shipdb where country like ? or currency like ?";
		Connection connection = null;
		PreparedStatement statement = null;
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
			statement = connection.prepareStatement(sql);
			statement.setString(1, searchterm + "%");
			statement.setString(2, searchterm + "%");
			ResultSet rs = statement.executeQuery();

			StringBuilder html = new StringBuilder();
			html.append(
					"<select name=\"shiploc\" id=\"shiploc\" style=\"width:440px;\" onClick=\"shipcost( ['shiploc','action__submitpayment'],['ddiv'] ); return true;\">\n");

			if (rs.next()) {
				html.append("<option selected>" + rs.getString(1) + "</option>\n");
				while (rs.next()) {
					html.append("<option>" + rs.getString(1) + "</option>\n");
				}
			}
			html.append("</select>\n");

			HttpServerResponse response = context.response();
			response.putHeader("Content-Type", "text/html");
			response.write(html.toString());
			response.end();
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

	private void doshipcost(RoutingContext context) {
		HttpServerRequest request = context.request();
		String shipto = request.getParam("args");

		String sql = "select * from shipdb where country = ?";
		Connection connection = null;
		PreparedStatement statement = null;
		PreparedStatement statement2 = null;
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
			statement = connection.prepareStatement(sql);
			statement.setString(1, shipto);
			ResultSet rs = statement.executeQuery();

			StringBuilder html = new StringBuilder();
			if (rs.next()) {
				html.append("BadStore.net can ship to:  <i>" + rs.getString(1) + "</i>!<br>");

				sql = "SELECT erate FROM eratedb WHERE code = '" + rs.getString(3) + "'";
				statement2 = connection.prepareStatement(sql);
				ResultSet rs2 = statement2.executeQuery();
				String erate;
				if (!rs2.next()) {
					erate = "[Call for Quote]";
				} else {
					erate = Float.toString(25 * rs2.getFloat(1));
				}

				html.append("Estimated Shipping Cost = <b> " + erate + " " + rs.getString(3) + "</b> ("
						+ rs.getString(2) + ")<br>");
			} else {
				html.append("<b>No Such Country/Currency: " + shipto + "</b>\n");
			}

			HttpServerResponse response = context.response();
			response.putHeader("Content-Type", "text/html");
			response.write(html.toString());
			response.end();
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
				if (statement2 != null) {
					statement2.close();
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

	private void Show_Form(RoutingContext context, String femail) {
		HttpServerResponse response = context.response();
		response.setChunked(true);
		response.putHeader("Content-Type", "text/html");

		Map<String, String> ref = new HashMap<>();
		String url = "badstore.cgi";
		ref.put("shipsearch", url);
		ref.put("shipcost", url);
		response.write(ajaxHeader(ref));

		response.write("<SCRIPT LANGUAGE=\"JavaScript\" SRC=\"/cardvrfy.js\"></SCRIPT>");
		response.write("<H2>Please enter shipping and credit card information:</H2><HR>");
		response.write("Enter the first few letters of and select the Ship To country:&nbsp;");
		response.write("<form>");
		response.write("<input type=\"text\" name=\"searchterm\" id=\"searchterm\" size=\"16\"");
		response.write(" onkeyup=\"shipsearch( ['searchterm','action__submitpayment'], ['rdiv'] ); return true;\">");
		response.write("<div id=\"rdiv\" style=\"width: 480px; margin-top: auto; overflow: auto; \"></div>");
		response.write(
				"<div id=\"ddiv\" style=\"width: 575px; margin-top: auto; overflow: auto; z-index: 1; \"></div>");
		response.write("</form>");
		response.write("<div id=\"id888\" style=\"margin-top: auto; \"><hr>");
		response.write(
				"<FORM METHOD=\"POST\" ACTION=\"/cgi-bin/badstore.cgi?action=order\" ENCTYPE=\"application/x-www-form-urlencoded\" ONSUBMIT=\"return DoCardvrfy(this);\">");
		response.write(femail);
		response.write(
				"Credit Card Number: <INPUT TYPE=\"text\" NAME=\"ccard\"  SIZE=16 MAXLENGTH=16>     Expiration Date: <INPUT TYPE=\"text\" NAME=\"expdate\"  SIZE=4><P><P><HR><P><Center>BadStore.net Accepts the following Payment Methods<P><IMG SRC=\"/images/amex.jpg\">&nbsp<IMG SRC=\"/images/discover.jpg\">&nbsp<IMG SRC=\"/images/jcb.gif\">&nbsp<IMG SRC=\"/images/mastercard.jpg\">&nbsp<IMG SRC=\"/images/visa.jpg\"><P> <INPUT TYPE=\"submit\" NAME=\"subccard\" VALUE=\"Place Order\"> </FORM></IMG></IMG></IMG></IMG>");
		response.write(footer());
		response.write("</div></BODY>");
		response.write("</HTML>");

		response.end();
	}

	/************************
	 * View Previous Orders *
	 ************************/
	public void viewprevious(RoutingContext context) {
		HttpServerResponse response = context.response();
		response.setChunked(true);

		/* Read SSOid Cookie */
		Cookie stemp = context.getCookie("SSOid");
		String email = null;
		String fullname = null;
		try {
			String ssoid = new String(Base64.getDecoder().decode(stemp.getValue()));
			String[] s_cookievalue = ssoid.split(":");
			email = s_cookievalue[0];
			fullname = s_cookievalue[2];
		} catch (Exception ignore) {
		}

		printHttpHeaders(response);
		response.write(header());
		response.write(start_html("BadStore.net - View Previous Orders"));
		response.write(h1("You have placed the following orders:"));
		response.write(hr());
		response.write(p());

		if (fullname == null || fullname.equals("")) {
			response.write(h2("You are not logged in!"));
			response.write(p());
			response.write("Use your browser's Back button and select Login.");
		} else {
			/* Connect to the SQL Database */
			Connection connection = null;
			PreparedStatement statement = null;
			try {
				connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
				statement = connection.prepareStatement(
						"SELECT orderdate, ordercost, orderitems, itemlist, ccard FROM orderdb WHERE accountid = '"
								+ email + "' ORDER BY orderdate,ordertime");
				ResultSet rs = statement.executeQuery();
				if (!rs.next()) {
					response.write(h2("You have no previous orders!"));
					response.write(p());
					response.write("Use your browser's Back button and select Login.");
				} else {

					response.write("<TABLE BORDER=1>");
					response.write(tr(
							th("Order Date") + th("Order Cost") + th("# Items") + th("Item List") + th("Card Used")));
					do {
						String ccard = rs.getString(5);
						ccard = ccard.replaceAll("(\\d\\d\\d\\d)[\\ \\s]?", "$1 ").replaceAll(" $", "");
						response.write(tr(td(rs.getString(1)) + td(rs.getString(2)) + td(rs.getString(3))
								+ td(rs.getString(4)) + td(ccard)));
					} while (rs.next());
					response.write("</TABLE>\n\n");
					response.write(p());
					response.write("<Center><i>Thank you for shopping at BadStore.net!</i></Center>");
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

		response.write(footer());
		response.write(end_html());
		response.end();
	}

	/************
	 * About Us *
	 ************/
	public void aboutus(RoutingContext context) {
		HttpServerResponse response = context.response();
		response.setChunked(true);

		printHttpHeaders(response);
		response.write(header());
		response.write(start_html("BadStore.net - About Us"));
		response.write(h2("About Us!") + hr() + p());
		response.write("<img src=\"/images/seal.jpg\" align=\"RIGHT\">");
		response.write(p() + "We value your comments, so click here and tell us what you think!  ");
		response.write(p() + "<A href=\"mailto:spam@badstore.net\">Send us an email!</a>");
		response.write(" with subject 'Howdy' and whatever you want to say" + p());
		response.write(
				"We may be a small site, but we really care about your on-line security.  That's why we undergo a Security Seal certification every few years or so.  The Security Seal is a stringent process where we have to fill out filecabinets full of paperwork to illustrate our security process.  Believe me, it's alot of work."
						+ p());
		response.write("SSL is also used for all critical processes - so hackers can't touch us!");

		response.write(footer());
		response.write(end_html());
		response.end();
	}

	/******************
	 * Supplier Login *
	 ******************/
	// TODO

	/*******************
	 * Supplier Portal *
	 ******************/
	// TODO

	/*******************
	 * Supplier Upload *
	 *******************/
	// TODO

	/**********************
	 * View Cart Contents *
	 **********************/
	public void cartview(RoutingContext context) {
		HttpServerResponse response = context.response();

		printHttpHeaders(response);
		response.write(header());
		response.write(start_html("BadStore.net - View Cart Contents"));
		response.write(h1("Keep Shopping!") + "<hr><p>");

		/* Read CartID Cookie */
		int items = 0;
		String cattitems = "";
		String price = "";
		try {
			Cookie temp = context.getCookie("CartID");
			String[] cookievalue = URLDecoder.decode(temp.getValue(), "UTF-8").split(":");
			items = Integer.parseInt(cookievalue[1]);
			float cost = Float.parseFloat(cookievalue[2]);
			price = String.format("$%.2f", cost);
			String[] tmp_cartitems = new String[cookievalue.length - 3];
			System.arraycopy(cookievalue, 3, tmp_cartitems, 0, tmp_cartitems.length);
			cattitems = String.join(",", tmp_cartitems);
		} catch (Exception ignore) {
		}

		if (items < 1) {
			response.write(h2("You have no items in your cart."));
			response.write("<p>");
			response.write(" Order something already!");
			response.write("<p>");
		} else {

			/* Connect to the SQL Database */
			Connection connection = null;
			PreparedStatement statement = null;
			try {
				connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());

				response.write(h2("The following items are in your cart:"));
				response.write("<p>");
				response.write(h3("Cart Contains:   " + items + " items at " + price));
				response.write("<p>");

				/* Prepare and Execute SQL Query */
				String sql = "SELECT itemnum, sdesc, ldesc, price FROM itemdb WHERE itemnum IN (" + cattitems + ")";
				statement = connection.prepareStatement(sql);
				ResultSet rs = statement.executeQuery();

				if (!rs.next()) {
					throw new RuntimeException("Item number not found: ");
				} else {
					/* Read the matching records and print them out */
					response.write(start_form("/cgi-bin/badstore.cgi?action=submitpayment"));
					response.write("<TABLE BORDER=1>");
					response.write(tr(
							th("ItemNum") + th("Item") + th("Description") + th("Price") + th("Image") + th("Order")));

					do {
						String image = "/images/" + rs.getInt(1) + ".jpg";
						response.write(tr(td(Integer.toString(rs.getInt(1))) + td(rs.getString(2)) + td(rs.getString(3))
								+ td(String.format("$%.2f", rs.getFloat(4)))
								+ td("align=\"CENTER\"", "<IMG SRC=" + image + ">") + td("align=\"CENTER\"",
										"<INPUT type=checkbox checked name='cartitem' value=" + rs.getInt(1) + ">")));
					} while (rs.next());
					response.write("</TABLE>\n\n");
					response.write("<p>");
					response.write("<Center>");
					response.write(submit("Place Order"));
					response.write("   ");
					response.write(reset());
					response.write("</Center>");
					response.write(end_form());
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
		response.write(footer());
		response.write("</BODY>\n");
		response.write("</HTML>\n");
		response.end();
	}

	/*********************
	 *** Print headers ***
	 *********************/
	static void printHttpHeaders(HttpServerResponse response) {
		response.putHeader("Content-Type", "text/html");
		response.putHeader("Server",
				"Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25");
		response.putHeader("ETag", "CPE1704TKS");
		response.putHeader("Cache-Control", "no-cache");
		response.putHeader("Pragma", "no-cache");
	}

	/*********************
	 * Login or Register *
	 *********************/
	public void loginregister(RoutingContext context) {
		HttpServerResponse response = context.response();
		response.setChunked(true);

		printHttpHeaders(response);
		response.write(header());
		response.write(start_html("BadStore.net - Register/Login"));
		response.write(h2("Login to Your Account or Register for a New Account"));
		response.write(hr());
		response.write(p());
		response.write(h3("Login to Your Account"));
		response.write(start_form("/cgi-bin/badstore.cgi?action=login"));
		response.write("Email Address:  ");
		response.write("<INPUT TYPE=\"text\" NAME=\"email\"  SIZE=20 MAXLENGTH=40>");
		response.write(p());
		response.write("Password:  ");
		response.write("<INPUT TYPE=\"password\" NAME=\"passwd\"  SIZE=8 MAXLENGTH=8>");
		response.write(p());
		response.write(submit("Login"));
		response.write(end_form());
		response.write(hr());
		response.write(p());
		response.write(h3("Register for a New Account"));
		response.write(start_form("/cgi-bin/badstore.cgi?action=register"));
		response.write("Full Name:  ");
		response.write("<INPUT TYPE=\"text\" NAME=\"fullname\"  SIZE=25 MAXLENGTH=40>");
		response.write(p());
		response.write("Email Address:  ");
		response.write("<INPUT TYPE=\"text\" NAME=\"email\"  SIZE=20 MAXLENGTH=40>");
		response.write(p());
		response.write("Password:  ");
		response.write("<INPUT TYPE=\"password\" NAME=\"passwd\"  SIZE=8 MAXLENGTH=8>");
		response.write(p());
		response.write("Password Hint - What's Your Favorite Color?:  ");
		response.write(
				"<SELECT NAME=\"pwdhint\"><OPTION  VALUE=\"green\">green<OPTION  VALUE=\"blue\">blue<OPTION  VALUE=\"red\">red<OPTION  VALUE=\"orange\">orange<OPTION  VALUE=\"purple\">purple<OPTION  VALUE=\"yellow\">yellow</SELECT>");
		response.write(p());
		response.write(
				"<font face=Arial size=2><i>(The Password Hint is used as a security measure to help recover a forgotten password.  You will need both your email address and this hint to access your account if you forget your current password.)</i></font>");
		response.write(p());
		response.write(hidden("role", "U"));
		response.write(submit("Register"));
		response.write(end_form());
		response.write(p());
		response.write(footer());
		response.write(end_html());
		response.end();
	}

	/**************
	 * My Account *
	 **************/
	public void myaccount(RoutingContext context) {
		HttpServerResponse response = context.response();
		response.setChunked(true);

		/* Read SSOid Cookie */
		Cookie stemp = context.getCookie("SSOid");
		String email = null;
		String fullname = null;
		String role = null;
		try {
			String ssoid = new String(Base64.getDecoder().decode(stemp.getValue()));
			String[] s_cookievalue = ssoid.split(":");
			email = s_cookievalue[0];
			fullname = s_cookievalue[2];
			role = s_cookievalue[3];
		} catch (Exception ignore) {
		}

		printHttpHeaders(response);
		response.write(header());
		response.write(start_html("BadStore.net - Register/Login", "/frmvrfy.js"));

		if (fullname == null || fullname.equals("")) {
			fullname = "{Unregistered User}";
			response.write(h2(" Welcome, as an " + fullname + " you can:"));
			response.write(p());
			response.write(
					"Login To Your Account / Register for A New Account - <A HREF='/cgi-bin/badstore.cgi?action=loginregister'>Click Here</A><BR>");
			response.write(p());
			response.write(" Reset A Forgotten Password");
			response.write(p());
			response.write(start_form("/cgi-bin/badstore.cgi?action=moduser"));
			response.write(
					"<font face=Arial size=2> Please enter the email addess and password hint you chose when the account was created:</font>");
			response.write(p());
			response.write(" Email Address:  ");
			response.write("<INPUT TYPE=\"text\" NAME=\"email\"  SIZE=15>");
			response.write(p());
			response.write(" Password Hint - What's Your Favorite Color?:  ");
			response.write(
					"<SELECT NAME=\"pwdhint\"><OPTION  VALUE=\"green\">green<OPTION  VALUE=\"blue\">blue<OPTION  VALUE=\"red\">red<OPTION  VALUE=\"orange\">orange<OPTION  VALUE=\"purple\">purple<OPTION  VALUE=\"yellow\">yellow</SELECT>");
			response.write(p());
			response.write(
					"<font face=Arial size=2><i> (The Password Hint was chosen when you registered for a new account as a security measure to help recover a forgotten password...)</i></font>");
			response.write(p());
			response.write(submit("DoMods", "Reset User Password"));
			response.write(end_form());
		} else {
			response.write(h2(" Welcome, " + fullname));
			response.write(hr());
			response.write(p());
			response.write("<B> Update your account information: </B>");
			response.write(p());
			response.write(p());
			response.write(start_form("/cgi-bin/badstore.cgi?action=moduser", "return DoPwdvrfy(this);"));
			response.write(" Current Full Name:  " + fullname);
			response.write(p());
			response.write(" New Full Name =  ");
			response.write("<INPUT TYPE=\"text\" NAME=\"fullname\"  SIZE=25 MAXLENGTH=40>");
			response.write(p());
			response.write(br());
			response.write(" Current Email Address:  " + email);
			response.write(p());
			response.write(" New Email Address =  ");
			response.write("<INPUT TYPE=\"text\" NAME=\"newemail\"  SIZE=20 MAXLENGTH=40>");
			response.write(p());
			response.write(br());
			response.write(" Change Password:  ");
			response.write("<INPUT TYPE=\"password\" NAME=\"newpasswd\"  SIZE=8 MAXLENGTH=8>");
			response.write("  Verify:  ");
			response.write("<INPUT TYPE=\"password\" NAME=\"vnewpasswd\"  SIZE=8 MAXLENGTH=8>");
			response.write(p());
			response.write(br());
			response.write(hidden("role", role));
			response.write(hidden("email", email));
			response.write(submit("DoMods", "Change Account"));
			response.write(end_form());
			response.write(p());
		}

		response.write(footer());
		response.write(end_html());
		response.end();
	}

	/**************************
	 * Modify User Attributes *
	 **************************/
	public void moduser(RoutingContext context) {
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();
		request.setExpectMultipart(true);
		request.endHandler(v -> {
			String aquery = request.getFormAttribute("DoMods");
			String email = request.getFormAttribute("email");
			String passwd = request.getFormAttribute("passwd");
			String pwdhint = request.getFormAttribute("pwdhint");
			String fullname = request.getFormAttribute("fullname");
			String role = request.getFormAttribute("role");
			String vnewpasswd = request.getFormAttribute("vnewpasswd");
			String newemail = request.getFormAttribute("newemail");

			if (email != null) {
				email = email.trim();
			}
			if (passwd != null) {
				passwd = passwd.trim();
			}
			if (pwdhint != null) {
				pwdhint = pwdhint.trim();
			}
			if (fullname != null) {
				fullname = fullname.trim();
			}
			if (role != null) {
				role = role.trim();
			}
			String newpasswd = "Welcome";
			String encpasswd = md5Hex(newpasswd);
			String vencpasswd = vnewpasswd == null ? null : md5Hex(vnewpasswd);
			printHttpHeaders(response);

			/* Connect to the SQL Database */
			Connection connection = null;
			Statement statement = null;
			try {
				connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
				statement = connection.createStatement();

				/* Reset User Password */
				if (aquery != null && aquery.equals("Reset User Password")) {
					response.write(header());
					response.write(start_html("BadStore.net - Reset Password for User"));
					/* Prepare and Execute SQL Query */
					statement.executeUpdate(
							"UPDATE userdb SET passwd = '" + encpasswd + "' WHERE email='" + email + "'");
					response.write(
							h2("The password for user:  " + email + p() + " ...has been reset to: " + newpasswd));
				} else if (aquery != null && aquery.equals("Add User")) {
					response.write(header());
					response.write(start_html("BadStore.net - Add User"));
					statement.executeUpdate("INSERT INTO userdb (email, passwd, pwdhint, fullname, role) VALUES ('"
							+ email + "','" + encpasswd + "','+" + pwdhint + "', '" + fullname + "', '" + role + "')");
					response.write(h2("User:  " + fullname + " has been added."));
				} else if (aquery != null && aquery.equals("Delete User")) {
					response.write(header());
					response.write(start_html("BadStore.net - Delete User"));
					statement.executeUpdate("DELETE FROM userdb WHERE email='" + email + "'");
					response.write(h2("User:  " + email + " has been deleted."));
				} else if (aquery != null && aquery.equals("Change Account")) {
					/* Change Account Information */
					response.write(header());
					response.write(start_html("BadStore.net - Update User Information"));
					statement
							.executeUpdate("UPDATE userdb SET fullname='" + fullname + "' WHERE email='" + email + "'");
					statement
							.executeUpdate("UPDATE userdb SET passwd='" + vencpasswd + "' WHERE email='" + email + "'");
					statement.executeUpdate("UPDATE userdb SET email='" + newemail + "' WHERE email='" + email + "'");
					response.write(h2(" Account Information for: "));
					response.write(" Full Name: ");
					response.write(fullname);
					response.write(p());
					response.write("Email: ");
					response.write(newemail);
					response.write(p());
					response.write(" Password: ");
					response.write(newpasswd);
					response.write(p());
					response.write(h3(" Has been updated!"));
				}
				response.write(footer());
				response.write(end_html());
				response.end();
			} catch (Exception e) {
				context.fail(e);
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
		});
	}

	/****************
	 * SOAP Updates *
	 ****************/
	// TODO

	/*************
	 * Auth User *
	 *************/
	public void authuser(RoutingContext context) {
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();
		request.setExpectMultipart(true);
		request.endHandler(v -> {
			String email = request.getFormAttribute("email");
			String passwd = request.getFormAttribute("passwd");
			String pwdhint = request.getFormAttribute("pwdhint");
			String fullname = request.getFormAttribute("fullname");
			if (fullname != null) {
				fullname = fullname.replaceAll("'", "&apos;");
			}
			String role = request.getFormAttribute("role");

			if (email != null) {
				email = email.trim();
			}
			if (passwd != null) {
				passwd = passwd.trim();
			}
			if (pwdhint != null) {
				pwdhint = pwdhint.trim();
			}
			if (fullname != null) {
				fullname = fullname.trim();
			}
			if (role != null) {
				role = role.trim();
			}

			passwd = md5Hex(passwd);

			/* Connect to the SQL Database */
			Connection connection = null;
			Statement statement = null;
			try {
				connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
				statement = connection.createStatement();

				String action = request.getParam("action");
				if (action.equals("login")) {
					ResultSet rs = null;
					try {
						rs = statement.executeQuery(
								"SELECT * FROM userdb WHERE email='" + email + "' AND passwd='" + passwd + "'");
					} catch (SQLException e) {
						response.putHeader("Location", "/cgi-bin/badstore.cgi?action=loginregister");
					}

					if (rs == null || !rs.next()) {
						printHttpHeaders(response);
						response.write(header());
						response.write(start_html("BadStore.net - Login Error"));
						response.write(h2("UserID and Password not found!"));
						response.write("Use your browser's Back button and try again.");
						response.write(footer());
						response.write(end_html());
						response.end();
						return;
					} else {
						/* Login credentials are valid */
						fullname = rs.getString(4);
						role = rs.getString(5);
						/* Close statement handles */
					}
				} else {
					/* Register for a new account as a normal user */
					/* Add ordered items to Order Database */
					statement.executeUpdate("INSERT INTO userdb (email, passwd, pwdhint, fullname, role) VALUES ('"
							+ email + "', '" + passwd + "','" + pwdhint + "', '" + fullname + "', '" + role + "')");
				}

				/* Set SSO Cookie */
				String cookievalue = String.join(":", new String[] { email, passwd, fullname, role });
				cookievalue = Base64.getEncoder().encodeToString(cookievalue.getBytes());
				Cookie cartcookie = Cookie.cookie("SSOid", cookievalue);
				cartcookie.setPath("/");
				context.addCookie(cartcookie);

				home(context);
			} catch (Exception e) {
				context.fail(e);
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
		});
	}

	/*****************************
	 * Test of New Functionality *
	 *****************************/
	public void test(RoutingContext context) {
		HttpServerRequest request = context.request();
		HttpServerResponse response = context.response();

		String squery = request.getParam("searchquery");

		try {
			Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.parse(new FileInputStream("htdocs/rss.xml"));
			document.getElementsByTagName("pubDate").item(0).setTextContent(getdate());
			document.getElementsByTagName("lastBuildDate").item(0).setTextContent(getdate());
			Node channel = document.getElementsByTagName("channel").item(0);
			NodeList items = document.getElementsByTagName("item");
			if (items.getLength() == 15) {
				Node lastItem = items.item(14);
				channel.removeChild(lastItem);
			}
			Node newItem = document.createElement("item");
			Node title = document.createElement("title");
			title.setTextContent("A Top Search Item at BadStore.net (BadStore.net)");
			Node link = document.createElement("link");
			link.setTextContent("http://www.badstore.net/cgi-bin/badstore.cgi?action=qsearch");
			Node guid = document.createElement("guid");
			guid.setTextContent("http://www.badstore.net/cgi-bin/badstore.cgi?action=&getdate");
			Node description = document.createElement("description");
			description.setTextContent(
					"<p><a href=\"http://www.badstore.net\"><img src=\"http://www.badstore.net/images/index.gif\" style=\"padding-left: 10px; padding-right: 10px; \" align=\"left\" alt=\"The Top Search Items at BadStore.net\" border=\"0\" /><a>BadStore.net Sales Operations Center - Here\'s what everybody else is looking for at BadStore.net!!!&nbsp If they all want it, you should too!<br><br><b>Search Item:</b>&nbsp "
							+ squery);
			newItem.appendChild(title);
			newItem.appendChild(link);
			newItem.appendChild(guid);
			newItem.appendChild(description);
			channel.insertBefore(newItem, items.item(0));

			TransformerFactory transFactory = TransformerFactory.newInstance();
			Transformer transformer = transFactory.newTransformer();

			FileOutputStream fos = new FileOutputStream(new File("htdocs/rss.xml"));
			StreamResult result = new StreamResult(fos);
			transformer.transform(new DOMSource(document), result);
			fos.close();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		/* Connect to the SQL Database */
		Connection connection = null;
		Statement statement = null;
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
			statement = connection.createStatement();
			String sql = "SELECT itemnum, sdesc, ldesc, price FROM itemdb WHERE '" + squery
					+ "' COLLATE nocase IN (itemnum,sdesc,ldesc)";
			ResultSet rs = statement.executeQuery(sql);

			printHttpHeaders(response);
			response.write(header());
			response.write(start_html("BadStore.net - Search Results"));
			response.write(comment("Search code developed by Bobby Jones - summer intern, 1996"));
			response.write(comment("Comment the $sql line out after troubleshooting is done"));

			if (!rs.next()) {
				response.write(h2("No items matched your search criteria: ") + sql);
			} else {
				response.write(h2("The following items matched your search criteria:"));
				response.write("<HR>");
				response.write(start_form("/cgi-bin/badstore.cgi?action=cartadd"));
				response.write("<TABLE BORDER=1>");
				response.write(tr(th("ItemNum") + th("Item") + th("Description") + th("Price") + th("Image")
						+ th("Add to Cart")));
				do {
					String image = "/images/" + rs.getInt(1) + ".jpg";
					response.write(tr(td(Integer.toString(rs.getInt(1))) + td(rs.getString(2)) + td(rs.getString(3))
							+ td(String.format("$%.2f", rs.getFloat(4)))
							+ td("align=\"CENTER\"", "<IMG SRC=" + image + ">") + td("align=\"CENTER\"",
									"<INPUT type=checkbox name=\"cartitem\" value=" + rs.getInt(1) + ">")));
				} while (rs.next());
				response.write("</TABLE>\n\n");
				response.write("<p>");
				response.write(submit("Add Items to Cart"));
				response.write("   ");
				response.write(reset());
				response.write("</Center>");
				response.write(end_form());
				response.write(footer());
				response.write(end_html());
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
		context.response().end();
	}

	private String md5Hex(String input) {
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			byte[] digest = md5.digest(input.getBytes());
			return DatatypeConverter.printHexBinary(digest);
		} catch (Exception ignore) {
			return null;
		}
	}
}

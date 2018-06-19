package badstore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

public class InitDBs extends CGI implements Handler<RoutingContext> {

	@Override
	public void handle(RoutingContext context) {
		initialize();
		HttpServerResponse response = context.response();
		response.putHeader("Content-Type", "text/html");
		response.setChunked(true)
				.write("<HTML><HEAD><B>BadStore.net - Database Reset</B></HEAD><BODY><p><hr><p><H1>Databases have been reset...</H1><p><BR><A HREF='/'>Click Here to go directly to BadStore.net</A></BODY></HTML>\n")
				.end();
	}

	public void initialize() {
		Connection connection = null;
		Statement statement = null;
		PreparedStatement prepared = null;
		try {
			File storeDir = BadStore.storeDir;
			if (!storeDir.exists()) {
				storeDir.mkdirs();
			} else if (!storeDir.isDirectory()) {
				throw new RuntimeException(storeDir.toString() + " is not directory.");
			}
			
			File uploadDir = BadStore.uploadDir;
			if (!uploadDir.exists()) {
				uploadDir.mkdirs();
			} else if (!uploadDir.isDirectory()) {
				throw new RuntimeException(uploadDir.toString() + " is not directory.");
			}

			File guestbookdb = BadStore.guestbookdb;
			if (guestbookdb.exists()) {
				guestbookdb.delete();
				guestbookdb.createNewFile();
			}

			File rssfile = BadStore.rssfile;
			if (rssfile.exists()) {
				rssfile.delete();
				rssfile.createNewFile();
			}

			File dbfile = BadStore.dbfile;
			if (dbfile.exists()) {
				dbfile.delete();
			}

			/* ### Create new databases and tables ### */
			connection = DriverManager.getConnection("jdbc:sqlite:" + dbfile.getAbsolutePath());
			connection.setAutoCommit(false);
			statement = connection.createStatement();

			// ### Create orderdb table
			statement.executeUpdate(
					"CREATE TABLE orderdb (sessid INTEGER, orderdate DATE, ordertime TIME, ordercost VARCHAR(10), orderitems INTEGER, itemlist VARCHAR(50), accountid VARCHAR(30), ipaddr VARCHAR(20), cartpaid VARCHAR(1), ccard VARCHAR(16), expdate VARCHAR(4))");
			// ### Add orders to orderdb
			StringBuilder sql = new StringBuilder();
			sql.append(
					"INSERT INTO orderdb VALUES (1078228766,DATE(),TIME(),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.50','Y','4111111111111111','0705'),");
			sql.append(
					"(1078228767,DATE(),TIME(),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.150','Y','5500000000000004','0905'),");
			sql.append(
					"(1078229834,DATE(DATE(),'-1 day'),TIME(TIME(),'-1 second'),'$22.95',1,'1008','joe@supplier.com','10.10.10.50','Y','4217639952372130','1008'),");
			sql.append(
					"(1078232948,DATE(DATE(),'-1 day'),TIME(TIME(),'-7502 second'),'$144.93',3,'1011,1012,1014','mary@spender.com','192.168.10.70','Y','3088000000000017','0506'),");
			sql.append(
					"(1078232048,DATE(DATE(),'-1 day'),TIME(),'$137.90',3,'1008,1009,1011','sue@spender.com','10.10.10.350','Y','6011000000000004','1006'),");
			sql.append(
					"(1078228766,DATE(),TIME(),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.50','Y','4111111111111111','0705'),");
			sql.append(
					"(1078228767,DATE(DATE(),'-2 day'),TIME(),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.150','Y','5500000000000004','0905'),");
			sql.append(
					"(1078229834,DATE(DATE(),'-2 day'),TIME(TIME(),'-29344 second'),'$22.95',1,'1008','joe@supplier.com','10.10.10.50','Y','341111111111111','1008'),");
			sql.append(
					"(1078232048,DATE(DATE(),'-2 day'),TIME(TIME(),'-9248 second'),'$137.90',3,'1008,1009,1011','mary@spender.com','192.168.10.70','Y','370000000000002','0506'),");
			sql.append(
					"(1078232048,DATE(DATE(),'-2 day'),TIME(),'$137.90',3,'1008,1009,1011','sue@spender.com','10.10.10.350','Y','6011000000000319','1006'),");
			sql.append(
					"(1078228766,DATE(DATE(),'-3 day'),TIME(),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.50','Y','4111111111111111','0705'),");
			sql.append(
					"(1078228767,DATE(DATE(),'-3 day'),TIME(),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.150','Y','5500000000000004','0905'),");
			sql.append(
					"(1078229834,DATE(DATE(),'-3 day'),TIME(),'$22.95',1,'1008','joe@supplier.com','10.10.10.50','Y','3747100000000000','1008'),");
			sql.append(
					"(1078232048,DATE(DATE(),'-3 day'),TIME(),'$137.90',3,'1008,1009,1011','mary@spender.com','192.168.10.70','Y','370000000000002','0506'),");
			sql.append(
					"(1078232048,DATE(DATE(),'-4 day'),TIME(TIME(),'-11162 second'),'$137.90',3,'1008,1009,1011','sue@spender.com','10.10.10.350','Y','6011000000000004','1006'),");
			sql.append(
					"(1078228766,DATE(DATE(),'-6 day'),TIME(TIME(),'-25328 second'),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.50','Y','4111111111111111','0705'),");
			sql.append(
					"(1078228767,DATE(DATE(),'-7 day'),TIME(),'$46.95',3,'1000,1003,1008','joe@supplier.com','10.10.10.150','Y','5500000000000004','0905'),");
			sql.append(
					"(1078229834,DATE(DATE(),'-13 day'),TIME(TIME(),'-7449 second'),'$22.95',1,'1008','joe@supplier.com','10.10.10.50','Y','3747100000000000','1008'),");
			sql.append(
					"(1078232048,DATE(DATE(),'-19 day'),TIME(),'$137.90',3,'1008,1009,1011','mary@spender.com','192.168.10.70','Y','370000000000002','0506'),");
			sql.append(
					"(1078232388,DATE(DATE(),'-19 day'),TIME(),'$1137.90',3,'1008,1009,1011','sue@spender.com','10.10.10.350','Y','6011000000000004','1006'),");
			sql.append(
					"(1078233380,DATE(DATE(),'-35 day'),TIME(),'$360.00',1,'1002','fred@newuser.com','172.22.15.47','Y','213100000000001','0705');");
			statement.executeUpdate(sql.toString());
			connection.commit();

			// ### Create userdb table
			statement.executeUpdate(
					"CREATE TABLE userdb (email VARCHAR(40), passwd VARCHAR(32) COLLATE nocase, pwdhint VARCHAR(8), fullname VARCHAR(50), role VARCHAR(1));");
			// ### Add users to userdb
			sql = new StringBuilder();
			sql.append(
					"INSERT INTO userdb VALUES ('AAA_Test_User','098F6BCD4621D373CADE4E832627B4F6','black','Test User','U'),");
			sql.append("('admin','5EBE2294ECD0E0F08EAB7690D2A6EE69','black','Master System Administrator','A'),");
			sql.append("('joe@supplier.com','62072d95acb588c7ee9d6fa0c6c85155','green','Joe Supplier','S'),");
			sql.append("('big@spender.com','9726255eec083aa56dc0449a21b33190','blue','Big Spender','U'),");
			sql.append("('ray@supplier.com','99b0e8da24e29e4ccb5d7d76e677c2ac','red','Ray Supplier','S'),");
			sql.append("('robert@spender.net','e40b34e3380d6d2b238762f0330fbd84','orange','Robert Spender','U'),");
			sql.append("('bill@gander.org','5f4dcc3b5aa765d61d8327deb882cf99','purple','Bill Gander','U'),");
			sql.append("('steve@badstore.net','8cb554127837a4002338c10a299289fb','red','Steve Owner','U'),");
			sql.append("('fred@whole.biz','356c9ee60e9da05301adc3bd96f6b383','yellow','Fred Wholesaler','U'),");
			sql.append("('debbie@supplier.com','2fbd38e6c6c4a64ef43fac3f0be7860e','green','Debby Supplier','S'),");
			sql.append("('mary@spender.com','7f43c1e438dc11a93d19616549d4b701','blue','Mary Spender','U'),");
			sql.append("('sue@spender.com','ea0520bf4d3bd7b9d6ac40c3d63dd500','orange','Sue Spender','U'),");
			sql.append("('curt@customer.com','0DF3DBF0EF9B6F1D49E88194D26AE243','green','Curt Wilson','U'),");
			sql.append("('paul@supplier.com','EB7D34C06CD6B561557D7EF389CDDA3C','red','Paul Rice','S'),");
			sql.append("('kevin@spender.com',NULL,NULL,'Kevin Richards','U'),");
			sql.append("('ryan@badstore.net','40C0BBDC4AEEAA39166825F8B477EDB4','purple','Ryan Shorter','A'),");
			sql.append("('stefan@supplier.com','8E0FAA8363D8EE4D377574AEE8DD992E','yellow','Stefan Drege','S'),");
			sql.append("('landon@whole.biz','29A4F8BFA56D3F970952AFC893355ABC','purple','Landon Scott','U'),");
			sql.append("('sam@customer.net','5EBE2294ECD0E0F08EAB7690D2A6EE69','red','Sam Rahman','U'),");
			sql.append("('david@customer.org','356779A9A1696714480F57FA3FB66D4C','blue','David Myers','U'),");
			sql.append("('john@customer.org','EEE86E9B0FE29B2D63C714B51CE54980','green','John Stiber','U'),");
			sql.append("('heinrich@supplier.de','5f4dcc3b5aa765d61d8327deb882cf99','red','Heinrich H√ºber','S'),");
			sql.append("('tommy@customer.net','7f43c1e438dc11a93d19616549d4b701','orange','Tom O''Kelley','U');");
			statement.executeUpdate(sql.toString());
			connection.commit();

			// ### Create itemdb table
			statement.executeUpdate(
					"CREATE TABLE itemdb (itemnum INTEGER, sdesc VARCHAR(20) COLLATE nocase, ldesc VARCHAR(40) COLLATE nocase, qty INTEGER, cost FLOAT(8,2), price FLOAT(8,2), isnew VARCHAR(1));");

			// #Add items to itemdb
			sql = new StringBuilder();
			sql.append("INSERT INTO itemdb VALUES (1000,'Snake Oil','Useless but expensive',5,4.35,11.50,'Y'),");
			sql.append("(1001,'Crystal Ball','The finest Austrian crystal for complete clarity',2,13.95,49.95,'N'),");
			sql.append("(1002,'Magic Hat','The classic magicians hat',7,18.45,60.00,'N'),");
			sql.append("(1003,'Magic Rabbit','Cute white bunny',27,3.50,12.50,'Y'),");
			sql.append("(1004,'Security Appliance','Everybody needs one',3,400,3999,'N'),");
			sql.append("(1005,'Perfect Code','The rarest magic of all',1,5,5000.00,'Y'),");
			sql.append("(1006,'Security Blanket','Keeps you warm and toasty',4,9.5,16.00,'N'),");
			sql.append("(1007,'Bag ''o Fud','For those who believe anything',9,.50,200,'N'),");
			sql.append("(1008,'ROI Calculator','Accurate Return on Investment',99,2.30,22.95,'Y'),");
			sql.append("(1009,'Planning Template','Business Planning Tool',2,6.7,24.95,'Y'),");
			sql.append("(1010,'Security 911','Technical Support Agreement',1,99,9999,'N'),");
			sql.append("(1011,'Money','There''s never enough',1,3,9500.00,'Y'),");
			sql.append("(1012,'Endless Cup','Perfect for late nights',74,4.56,23.98,'Y'),");
			sql.append("(1013,'Invisibility Cloak','For when you just want to hide',1,0,8995,'N'),");
			sql.append("(1014,'Disappearing Ink','Makes perfect signatures',43,8.96,30.95,'Y'),");
			sql.append("(9999,'Test','Test Item',0,0,0,'N');");
			statement.executeUpdate(sql.toString());
			connection.commit();

			// ### Create acctdb table
			statement.executeUpdate(
					"CREATE TABLE acctdb (invnum VARCHAR(20), amount FLOAT(8,2), status VARCHAR(10), paidon DATE, bankinfo VARCHAR(20), rma CHAR(1));");
			// #Add items to acctdb
			sql = new StringBuilder();
			sql.append("INSERT INTO acctdb VALUES ('MS-45921',4976.48,'Paid',DATE(),'33011:38349873766',0),");
			sql.append("('MS-45876',983.93,'Submitted',DATE(),'33011:38349873766',1),");
			sql.append("('MS-45873',34897.21,'Received',DATE(DATE(),'-1 day'),'78011:38334587297',0);");
			statement.executeUpdate(sql.toString());

			// ### Create and populate Shipdb table ###
			statement.executeUpdate("CREATE TABLE shipdb (country VARCHAR(30), currency VARCHAR(30), code VARCHAR(3))");
			connection.commit();

			InputStream is = null;
			try {
				is = getClass().getResourceAsStream("shipdb.xml");
				DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
				Document document = builder.parse(is);
				XPath xpath = XPathFactory.newInstance().newXPath();

				NodeList nodelist = (NodeList) xpath.evaluate("//row", document, XPathConstants.NODESET);
				prepared = connection.prepareStatement("INSERT INTO shipdb (country, currency, code) VALUES (?,?,?)");

				for (int i = 0; i < nodelist.getLength(); i++) {
					Node row = nodelist.item(i);
					String country = ((Node) xpath.evaluate("country", row, XPathConstants.NODE)).getTextContent();
					String currency = ((Node) xpath.evaluate("currency", row, XPathConstants.NODE)).getTextContent();
					String code = ((Node) xpath.evaluate("code", row, XPathConstants.NODE)).getTextContent();
					prepared.setString(1, country);
					prepared.setString(2, currency);
					prepared.setString(3, code);
					prepared.addBatch();
				}
				prepared.executeBatch();

				// ### Create and populate eratedb table ###
				statement.executeUpdate(
						"CREATE TABLE eratedb (code VARCHAR(3), currency VARCHAR(30), erate FLOAT(6,4))");
				connection.commit();
			} catch (IOException e) {
				connection.rollback();
				throw new RuntimeException(e);
			} finally {
				if (is != null) {
					try {
						is.close();
					} catch (IOException ignore) {
					}
				}
				if (prepared != null) {
					try {
						prepared.close();
					} catch (SQLException ignore) {
					}
				}
			}

			try {
				is = getClass().getResourceAsStream("eratedb.xml");
				DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
				Document document = builder.parse(is);
				XPath xpath = XPathFactory.newInstance().newXPath();

				NodeList nodelist = (NodeList) xpath.evaluate("//row", document, XPathConstants.NODESET);
				prepared = connection.prepareStatement("INSERT INTO eratedb (code, currency, erate) VALUES (?,?,?)");

				for (int i = 0; i < nodelist.getLength(); i++) {
					Node row = nodelist.item(i);
					String code = ((Node) xpath.evaluate("code", row, XPathConstants.NODE)).getTextContent();
					String currency = ((Node) xpath.evaluate("currency", row, XPathConstants.NODE)).getTextContent();
					String erate = ((Node) xpath.evaluate("erate", row, XPathConstants.NODE)).getTextContent();
					prepared.setString(1, code);
					prepared.setString(2, currency);
					prepared.setString(3, erate);
					prepared.addBatch();
				}
				prepared.executeBatch();
				connection.commit();
			} catch (IOException e) {
				connection.rollback();
				throw new RuntimeException(e);
			} finally {
				if (is != null) {
					try {
						is.close();
					} catch (IOException ignore) {
					}
				}
				if (prepared != null) {
					try {
						prepared.close();
					} catch (SQLException ignore) {
					}
				}
			}

			// ### Create Guestbookdb file ###
			PrintStream guestbook = new PrintStream(guestbookdb);
			guestbook.println(
					"Wednesday, February 18, 2004 at 07:42:34~Joe Shopper~joe@microsoft.com~This is a great site!  I'm going to shop here every day.");
			guestbook.println(
					"Wednesday, February 18, 2004 at 11:41:07~John Q. Public~jqp@whitehouse.gov~Let me know when the summer items are in.");
			guestbook.println(
					"Friday, February 20, 2004 at 14:05:22~Big Spender~billg@microsoft.com~Where's the big ticket items?");
			guestbook.println(
					"Sunday, February 22, 2004 at 06:16:05~Evil Hacker~s8n@haxor.com~You have no security!  I can own your site in less than 2 minutes.  Pay me $100,000 US currency by the end of day Friday, or I will hack you offline and sell the credit card numbers I found on your site.  Send the money direct to my PayPal account.");
			guestbook.close();

			// ### Create RSS file ###
			Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.parse(getClass().getResourceAsStream("rss.xml"));
			document.getElementsByTagName("pubDate").item(0).setTextContent(getdate());
			document.getElementsByTagName("lastBuildDate").item(0).setTextContent(getdate());

			TransformerFactory transFactory = TransformerFactory.newInstance();
			Transformer transformer = transFactory.newTransformer();

			DOMSource source = new DOMSource(document);
			FileOutputStream os = new FileOutputStream(rssfile);
			StreamResult result = new StreamResult(os);
			transformer.transform(source, result);
			os.close();

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			try {
				if (prepared != null) {
					prepared.close();
				}
			} catch (SQLException ignore) {
			}
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

	static String getdate() {
		SimpleDateFormat format = new SimpleDateFormat("EEEE, MMMM dd, yyyy 'at' HH:mm:ss");
		return format.format(new Date());
	}
}

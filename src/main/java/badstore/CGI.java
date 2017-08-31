package badstore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class CGI {
	private String createJjavascript(Map<String, String> ref) {
		StringBuilder builder = new StringBuilder();
		builder.append("<script type=\"text/javascript\">\n");
		builder.append("//<![CDATA[\n");

		BufferedReader reader = null;
		try {
			InputStream is = getClass().getResourceAsStream("ajax_common.js");
			reader = new BufferedReader(new InputStreamReader(is));
			String line;
			while ((line = reader.readLine()) != null) {
				builder.append(line);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (reader != null)
					reader.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}

		for (Map.Entry<String, String> entry : ref.entrySet()) {
			String funcName = entry.getKey();
			String url = entry.getValue();
			if (url.contains("?")) {
				url = url + "&";
			} else {
				url = url + "?";
			}
			builder.append("function " + funcName + "() {");
			builder.append("	  var args = " + funcName + ".arguments;");
			builder.append("	  for( var i=0; i<args[0].length;i++ ) {");
			builder.append("	    args[0][i] = fnsplit(args[0][i]);");
			builder.append("	  }");
			builder.append("	  var l = ajax.length;");
			builder.append("	  ajax[l]= new pjx(args,\"" + funcName + "\",args[2]);");
			builder.append("	  ajax[l].url = \"" + url + "\" + ajax[l].url;");
			builder.append("	  ajax[l].send2perl();");
			builder.append("	}");
		}
		builder.append("\n//]]>");
		builder.append("</script>");

		return builder.toString();
	}

	String ajaxHeader(Map<String, String> ref) {
		StringBuilder builder = new StringBuilder();
		String javascript = createJjavascript(ref);
		BufferedReader reader = null;
		try {
			InputStream is = getClass().getResourceAsStream("header.txt");
			reader = new BufferedReader(new InputStreamReader(is));
			String line;
			while ((line = reader.readLine()) != null) {
				builder.append(line);
				builder.append("\n");
				if (line.equals("  <head>")) {
					builder.append(javascript);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (reader != null)
					reader.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return builder.toString();
	}

	String header() {
		BufferedReader reader = null;
		StringBuilder builder = new StringBuilder();
		try {
			InputStream is = getClass().getResourceAsStream("header.txt");
			reader = new BufferedReader(new InputStreamReader(is));
			String line;
			while ((line = reader.readLine()) != null) {
				builder.append(line);
				builder.append("\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (reader != null)
					reader.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return builder.toString();
	}

	String footer() {
		BufferedReader reader = null;
		StringBuilder builder = new StringBuilder();
		try {
			InputStream is = getClass().getResourceAsStream("footer.txt");
			reader = new BufferedReader(new InputStreamReader(is));
			String line;
			while ((line = reader.readLine()) != null) {
				builder.append(line);
				builder.append("\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (reader != null)
					reader.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return builder.toString();
	}

	static String start_html(String title) {
		StringBuilder builder = new StringBuilder();
		builder.append("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML//EN\"><HTML><HEAD><TITLE>");
		builder.append(title);
		builder.append("</TITLE></HEAD><BODY>");
		return builder.toString();
	}

	static String start_html(String title, String script) {
		StringBuilder builder = new StringBuilder();
		builder.append("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML//EN\"><HTML><HEAD><TITLE>");
		builder.append(title);
		builder.append("</TITLE>");
		builder.append("<SCRIPT LANGUAGE=\"JavaScript\" SRC=\"");
		builder.append(script);
		builder.append("\"></SCRIPT>");
		builder.append("</HEAD><BODY>");
		return builder.toString();
	}

	static String end_html() {
		return "</BODY></HTML>";
	}

	static String comment(String str) {
		return "<!-- " + str + " -->";
	}

	static String h1(String str) {
		return "<h1>" + str + "</h1>";
	}

	static String h2(String str) {
		return "<h2>" + str + "</h2>";
	}

	static String h3(String str) {
		return "<h3>" + str + "</h3>";
	}

	static String start_form(String action) {
		return "<FORM METHOD=\"POST\" ACTION=\"" + action + "\" ENCTYPE=\"application/x-www-form-urlencoded\">";
	}

	static String start_form(String action, String onSubmit) {
		return "<FORM METHOD=\"POST\" ACTION=\"" + action
				+ "\" ENCTYPE=\"application/x-www-form-urlencoded\" ONSUBMIT=\"" + onSubmit + "\">";
	}

	static String tr(String str) {
		return "<tr>" + str + "</tr>";
	}

	static String th(String str) {
		return "<th>" + str + "</th>";
	}

	static String td(String str) {
		return "<td>" + str + "</td>";
	}

	static String td(String attr, String str) {
		return "<td " + attr + ">" + str + "</td>";
	}

	static String submit(String str) {
		return "<INPUT TYPE=\"submit\" NAME=\"" + str + "\" VALUE=\"" + str + "\">";
	}

	static String submit(String name, String value) {
		return "<INPUT TYPE=\"submit\" NAME=\"" + name + "\" VALUE=\"" + value + "\">";
	}

	static String hidden(String name, String value) {
		return "<INPUT TYPE=\"hidden\" NAME=\"" + name + "\" VALUE=\"" + value + "\">";
	}

	static String reset() {
		return "<INPUT TYPE=\"reset\">";
	}

	static String end_form() {
		return "</FORM>";
	}

	static String hr() {
		return "<hr>";
	}

	static String br() {
		return "<br>";
	}

	static String p() {
		return "<p>";
	}

}

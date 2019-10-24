+++
author = "pwntester"
date = 2012-11-05T09:18:00Z
description = ""
draft = false
slug = "fourgoats-vulnerabilities-promiscuous-ssl-trustmanager"
title = "FourGoats Vulnerabilities: Promiscuous SSL TrustManager"

+++

The login activity uses an asynchronous task to validate the user credentials. The ValidateCredsAsyncTask performs this validation

```
private class ValidateCredsAsyncTask extends
		AsyncTask<Void, Void, HashMap<String, String>> {

	Login mActivity;

	public ValidateCredsAsyncTask(Login activity) {
		mActivity = activity;
	}

	@Override
	protected HashMap<String, String> doInBackground(Void... params) {
		LoginRequest client = new LoginRequest(context);
		String userName = userNameEditText.getText().toString();
		String password = passwordEditText.getText().toString();
		boolean rememberMe = rememberMeCheckBox.isChecked();
		HashMap<String, String> userInfo = new HashMap<String, String>();
		if (allFieldsCompleted(userName, password)) {
			UserInfoDBHelper dbHelper = new UserInfoDBHelper(context);
			try {
				userInfo = client.validateCredentials(userName, password);
				if (userInfo.get("success").equals("false"))
					userInfo.put("errors", Constants.LOGIN_FAILED);
				else {
					dbHelper.deleteInfo();
					dbHelper.insertSettings(userInfo);
					if (rememberMe)
						saveCredentials(userName, password);
					// our secret backdoor account
					if (userName.equals("customerservice")
							&& password.equals("Acc0uNTM@n@g3mEnT"))
						userInfo.put("isAdmin", "true");
				}
			} catch (Exception e) {
				userInfo.put("errors", Constants.COULD_NOT_CONNECT);
				userInfo.put("success", "false");
				Log.w("Failed login", "Login with "
						+ userNameEditText.getText().toString() + " "
						+ passwordEditText.getText().toString() + " failed");
			} finally {
				dbHelper.close();
			}
		} else {
			userInfo.put("error", Constants.ALL_FIELDS_REQUIRED);
			userInfo.put("success", "false");
		}

		return userInfo;
	}

	protected void onPostExecute(HashMap<String, String> results) {
		if (results.get("success").equals("true")) {
			if (!previousActivity.isEmpty()) {
				ComponentName toLaunch = new ComponentName(
						"org.owasp.goatdroid.fourgoats", previousActivity);
				Intent intent = new Intent();
				intent.addCategory(Intent.CATEGORY_LAUNCHER);
				intent.setComponent(toLaunch);
				intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
				startActivity(intent);
			} else if (results.get("isAdmin").equals("true")) {
				Intent intent = new Intent(mActivity, AdminHome.class);
				startActivity(intent);
			} else {
				Intent intent = new Intent(mActivity, Home.class);
				startActivity(intent);
			}
		} else {
			Utils.makeToast(context, results.get("errors"),
					Toast.LENGTH_LONG);
		}
	}
}
```
The doInBackground method will execute the task and the first thing it does is to get an instance of LoginRequest that will perform the validation, so lets take a look at this method:

```
public HashMap<String, String> validateCredentials(String userName,
		String password) throws Exception {

	RestClient client = new RestClient("https://" + destinationInfo
			+ "/fourgoats/api/v1/login/authenticate");
	client.AddParam("userName", userName);
	client.AddParam("password", password);
	client.Execute(RequestMethod.POST, context);

	return LoginResponse.parseLoginResponse(client.getResponse());
}
```

It basically instanciates a RestClient that sends a POST request to a RESTful API to validate the credentials. The URL used states that it is using the SSL protocol to send the credentials out the wire (https://" + destinationInfo + "/fourgoats/api/v1/login/authenticate). So far so god, it looks secure! :) or not?

Lets take a deeper look to the RestClient Class.

RestClient exposes a method to execute requests (execute) that basically wraps up the executeRequest method:

```
private void executeRequest(HttpUriRequest request, String url,
		Context context) {

	HttpClient client = CustomSSLSocketFactory.getNewHttpClient();
	HashMap<String, String> proxyInfo = Utils.getProxyMap(context);
	String proxyHost = proxyInfo.get("proxyHost");
	String proxyPort = proxyInfo.get("proxyPort");

	if (!(proxyHost.equals("") || proxyPort.equals(""))) {
		HttpHost proxy = new HttpHost(proxyHost,
				Integer.parseInt(proxyPort));
		client.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY,
				proxy);
	}
	HttpResponse httpResponse;

	try {
		httpResponse = client.execute(request);
		responseCode = httpResponse.getStatusLine().getStatusCode();
		message = httpResponse.getStatusLine().getReasonPhrase();

		HttpEntity entity = httpResponse.getEntity();

		if (entity != null) {

			InputStream instream = entity.getContent();
			response = convertStreamToString(instream);

			// Closing the input stream will trigger connection release
			instream.close();
		}

	} catch (ClientProtocolException e) {
		client.getConnectionManager().shutdown();
	} catch (IOException e) {
		client.getConnectionManager().shutdown();
	}
}
```

We are using an HTTPClient to send the request but we are getting the HTTPClient from a custom SSLSocket Factory. This really start to smell relly bad. Custom SSL Socket Factory are words that we should not see in the same sentance!

And here things start looking pretty ugly.

CustomSSLSocketFactory is extending SSSocketFactory and initializating its SSLContext with a custom and promiscuous TrustManager:

```
public CustomSSLSocketFactory(KeyStore truststore)
		throws NoSuchAlgorithmException, KeyManagementException,
		KeyStoreException, UnrecoverableKeyException {
	super(truststore);

	TrustManager tm = new X509TrustManager() {
		public java.security.cert.X509Certificate[] getAcceptedIssuers() {
			return null;
		}

		@Override
		public void checkClientTrusted(
				java.security.cert.X509Certificate[] chain, String authType)
				throws java.security.cert.CertificateException {
			// TODO Auto-generated method stub

		}

		@Override
		public void checkServerTrusted(
				java.security.cert.X509Certificate[] chain, String authType)
				throws java.security.cert.CertificateException {
			// TODO Auto-generated method stub

		}
	};

	sslContext.init(null, new TrustManager[] { tm }, null);
}
```

This TrustManager is not throwing any java.security.cert.CertificateException so it will trust any certificate presented making it useless to use SSL!

You can use any intercepting proxy and present any certificate to the application, FourGoats will trust it and send the credentials using your certificate through your proxy!

Unfortunately, this is something that happens quite often when developers start having problems with server certificates. After trying it a couple of times, some of them just give up and implement a trust-all trust manager.

You can find plenty of questions in StackOverflow asking how to trust any certificates:

[http://stackoverflow.com/questions/2642777/trusting-all-certificates-using-httpclient-over-https](http://stackoverflow.com/questions/2642777/trusting-all-certificates-using-httpclient-over-https)

The good news is that you can also find good articles on how to use SSL properly to import your own certificates without ending up trusting everyone:

[http://nelenkov.blogspot.com.es/2011/12/using-custom-certificate-trust-store-on.html](http://nelenkov.blogspot.com.es/2011/12/using-custom-certificate-trust-store-on.html)

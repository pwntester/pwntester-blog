+++
author = "pwntester"
date = 2012-11-05T09:18:00Z
description = ""
draft = false
slug = "fourgoats-vulnerabilities-promiscuous-ssl-hostname-verifier"
title = "FourGoats Vulnerabilities: Promiscuous SSL HostName Verifier"

+++

Continuing the previous post ...

RestClient was getting an HttpClient instance using the CustomSSLSocketFactory.getNewHttpClient static method:

```
public static HttpClient getNewHttpClient() {
	try {
		KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		trustStore.load(null, null);
		SSLSocketFactory sf = new CustomSSLSocketFactory(trustStore);
		sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		HttpParams params = new BasicHttpParams();
		SchemeRegistry registry = new SchemeRegistry();
		registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
		registry.register(new Scheme("https", sf, 443));

		ClientConnectionManager ccm = new ThreadSafeClientConnManager(params, registry);
		return new DefaultHttpClient(ccm, params);
	} catch (Exception e) {
		return new DefaultHttpClient();
	}
}
```

Can you spot another, related, vulnerability?

So either if we set up a secure TrustManager for the SSL Socket Factory using the default TrustManager that uses the Android KeyStore, we are setting its HostNameVerifier to ALLOW_ALL_HOSTNAME_VERIFIER.

So, again, if we have a legit certificate signed by any trusted CA (in the Android KeyStore) for our own domain, we will be able to use it to perform a man-in-the-middle attack since the SSL TrustManager will trust the certificate as it is signed by a trusted CA but then it will fail to verify that the certificate was issued for the server we are connecting to.

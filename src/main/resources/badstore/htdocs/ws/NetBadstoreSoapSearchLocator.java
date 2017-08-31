/**
 * NetBadstoreSoapSearchLocator.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.2 May 03, 2005 (02:20:24 EDT) WSDL2Java emitter.
 */

package net.badstore.www.cgi_bin.soapsearch_cgi;

public class NetBadstoreSoapSearchLocator extends org.apache.axis.client.Service implements net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearch {

    public NetBadstoreSoapSearchLocator() {
    }


    public NetBadstoreSoapSearchLocator(org.apache.axis.EngineConfiguration config) {
        super(config);
    }

    public NetBadstoreSoapSearchLocator(java.lang.String wsdlLoc, javax.xml.namespace.QName sName) throws javax.xml.rpc.ServiceException {
        super(wsdlLoc, sName);
    }

    // Use to get a proxy class for NetBadstoreSoapSearchSoap
    private java.lang.String NetBadstoreSoapSearchSoap_address = "http://www.badstore.net/cgi-bin/soapsearch.cgi";

    public java.lang.String getNetBadstoreSoapSearchSoapAddress() {
        return NetBadstoreSoapSearchSoap_address;
    }

    // The WSDD service name defaults to the port name.
    private java.lang.String NetBadstoreSoapSearchSoapWSDDServiceName = "net.badstore.soapSearchSoap";

    public java.lang.String getNetBadstoreSoapSearchSoapWSDDServiceName() {
        return NetBadstoreSoapSearchSoapWSDDServiceName;
    }

    public void setNetBadstoreSoapSearchSoapWSDDServiceName(java.lang.String name) {
        NetBadstoreSoapSearchSoapWSDDServiceName = name;
    }

    public net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearchSoap getNetBadstoreSoapSearchSoap() throws javax.xml.rpc.ServiceException {
       java.net.URL endpoint;
        try {
            endpoint = new java.net.URL(NetBadstoreSoapSearchSoap_address);
        }
        catch (java.net.MalformedURLException e) {
            throw new javax.xml.rpc.ServiceException(e);
        }
        return getNetBadstoreSoapSearchSoap(endpoint);
    }

    public net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearchSoap getNetBadstoreSoapSearchSoap(java.net.URL portAddress) throws javax.xml.rpc.ServiceException {
        try {
            net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearchSoapStub _stub = new net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearchSoapStub(portAddress, this);
            _stub.setPortName(getNetBadstoreSoapSearchSoapWSDDServiceName());
            return _stub;
        }
        catch (org.apache.axis.AxisFault e) {
            return null;
        }
    }

    public void setNetBadstoreSoapSearchSoapEndpointAddress(java.lang.String address) {
        NetBadstoreSoapSearchSoap_address = address;
    }

    /**
     * For the given interface, get the stub implementation.
     * If this service has no port for the given interface,
     * then ServiceException is thrown.
     */
    public java.rmi.Remote getPort(Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
        try {
            if (net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearchSoap.class.isAssignableFrom(serviceEndpointInterface)) {
                net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearchSoapStub _stub = new net.badstore.www.cgi_bin.soapsearch_cgi.NetBadstoreSoapSearchSoapStub(new java.net.URL(NetBadstoreSoapSearchSoap_address), this);
                _stub.setPortName(getNetBadstoreSoapSearchSoapWSDDServiceName());
                return _stub;
            }
        }
        catch (java.lang.Throwable t) {
            throw new javax.xml.rpc.ServiceException(t);
        }
        throw new javax.xml.rpc.ServiceException("There is no stub implementation for the interface:  " + (serviceEndpointInterface == null ? "null" : serviceEndpointInterface.getName()));
    }

    /**
     * For the given interface, get the stub implementation.
     * If this service has no port for the given interface,
     * then ServiceException is thrown.
     */
    public java.rmi.Remote getPort(javax.xml.namespace.QName portName, Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
        if (portName == null) {
            return getPort(serviceEndpointInterface);
        }
        java.lang.String inputPortName = portName.getLocalPart();
        if ("net.badstore.soapSearchSoap".equals(inputPortName)) {
            return getNetBadstoreSoapSearchSoap();
        }
        else  {
            java.rmi.Remote _stub = getPort(serviceEndpointInterface);
            ((org.apache.axis.client.Stub) _stub).setPortName(portName);
            return _stub;
        }
    }

    public javax.xml.namespace.QName getServiceName() {
        return new javax.xml.namespace.QName("http://www.badstore.net/cgi-bin/soapsearch.cgi", "net.badstore.soapSearch");
    }

    private java.util.HashSet ports = null;

    public java.util.Iterator getPorts() {
        if (ports == null) {
            ports = new java.util.HashSet();
            ports.add(new javax.xml.namespace.QName("http://www.badstore.net/cgi-bin/soapsearch.cgi", "net.badstore.soapSearchSoap"));
        }
        return ports.iterator();
    }

    /**
    * Set the endpoint address for the specified port name.
    */
    public void setEndpointAddress(java.lang.String portName, java.lang.String address) throws javax.xml.rpc.ServiceException {
        if ("NetBadstoreSoapSearchSoap".equals(portName)) {
            setNetBadstoreSoapSearchSoapEndpointAddress(address);
        }
        else { // Unknown Port Name
            throw new javax.xml.rpc.ServiceException(" Cannot set Endpoint Address for Unknown Port" + portName);
        }
    }

    /**
    * Set the endpoint address for the specified port name.
    */
    public void setEndpointAddress(javax.xml.namespace.QName portName, java.lang.String address) throws javax.xml.rpc.ServiceException {
        setEndpointAddress(portName.getLocalPart(), address);
    }

}

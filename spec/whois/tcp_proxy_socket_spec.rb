require "spec_helper"

describe Whois::TCPProxySocket do
  let(:proxy_options) { { :host => '9.9.9.9', :port => 55555, :user => 'user',
                          :pass => 'pass' } }

  before(:each) do
    TCPSocket.stubs(:new).returns(stub(:puts => nil, :gets => nil))
  end

  describe '#http_connect' do
    it 'should do an http 1.0 connect to the proxy server' do
      @socket = klass.new('127.0.0.1', 43, nil, nil, proxy_options)
      @socket.send(:http_connect).should == [
        "CONNECT 127.0.0.1:43 HTTP/1.0",
        "Proxy-Authorization: Basic dXNlcjpwYXNz",
        "Connection: Keep-Alive",
        ""
      ]
    end
  end
end

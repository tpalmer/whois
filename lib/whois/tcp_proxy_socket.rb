require 'base64'
require 'socket'

module Whois
  class TCPProxySocket
    attr_reader :tcp_socket

    def initialize(*args)
      @host = args.shift
      @port = args.shift
      @proxy_options = args.pop
      @tcp_socket = TCPSocket.new(@proxy_options[:host], @proxy_options[:port], *args)
      http_connect.each {|line| @tcp_socket.puts line }
    end

    private

    def http_connect
      [
        "CONNECT #{@host}:#{@port} HTTP/1.1",
        basic_auth_header,
        ""
      ]
    end

    def basic_auth_header
      "Proxy-Authorization: Basic " +
        Base64.strict_encode64("#{@proxy_options[:user]}:#{@proxy_options[:pass]}")
    end
  end
end

require 'base64'
require 'socket'

module Whois
  class TCPProxySocket
    attr_accessor :host, :port, :proxy_options, :tcp_socket

    def initialize(*args)
      self.host = args.shift
      self.port = args.shift
      self.proxy_options = args.pop
      self.tcp_socket = TCPSocket.new(proxy_options[:host], proxy_options[:port], *args)

      http_connect.each do |line|
        tcp_socket.puts line
      end
    end

    private

    def basic_auth_header
      "Proxy-Authorization: Basic #{encoded_credentials}"
    end

    def encoded_credentials
      Base64.strict_encode64 "#{proxy_options[:user]}:#{proxy_options[:pass]}"
    end

    def http_connect
      [
        "CONNECT #{host}:#{port} HTTP/1.1",
        basic_auth_header,
        ""
      ]
    end
  end
end

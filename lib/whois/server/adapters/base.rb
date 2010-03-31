#
# = Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
#
# Category::    Net
# Package::     Whois
# Author::      Simone Carletti <weppos@weppos.net>
# License::     MIT License
#
#--
#
#++


require 'whois/answer/part'
require 'whois/answer'
require 'net/protocol'
require 'socket'


module Whois
  class Server
    module Adapters

      class Base
        include Socket::Constants

        # Default Whois request port.
        DEFAULT_WHOIS_PORT = 43

        attr_reader :type
        attr_reader :allocation
        attr_reader :host
        attr_reader :options
        attr_reader :buffer

        def initialize(type, allocation, host, options = {})
          @type       = type
          @allocation = allocation
          @host       = host
          @options    = options || {}
        end

        # Performs a Whois query for <tt>qstring</tt> 
        # using current server adapter and returns a <tt>Whois::Response</tt>
        # instance with the result of the request.
        #
        # server.query("google.com")
        # # => Whois::Response
        #
        def query(qstring)
          with_buffer do |buffer|
            request(qstring)
            Answer.new(self, buffer)
          end
        end

        def request(qstring)
          raise NotImplementedError
        end


        protected

          def with_buffer(&block)
            @buffer = []
            result = yield(@buffer)
            # @buffer = []
            # result
          end

          # Store an answer part in <tt>@buffer</tt>.
          def append_to_buffer(response, host)
            @buffer << ::Whois::Answer::Part.new(response, host)
          end

          def query_the_socket(qstring, host, port = nil)
            ask_the_socket(qstring, host, port || options[:port] || DEFAULT_WHOIS_PORT)
          end


        private

          def ask_the_socket(qstring, host, port)
            socket = connect_to(host, port, nil)
            socket.setsockopt Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1
            socket.write("#{qstring}\r\n")  # I could use put(foo) and forget the \n
            socket.read                     # but write/read is more symmetric than puts/read
          ensure                            # and I really want to use read instead of gets.
            socket.close if socket          # If != socket something went wrong.
          end

          def connect_to(host, port, timeout = nil)
            sock = nil
            if timeout
              Timeout::timeout(timeout) do
                sock = TCPSocket.new(host, port)
              end
            else
              sock = TCPSocket.new(host, port)
            end

            io = BufferedIO.new(sock)
            io.read_timeout = timeout
            # Getting reports from several customers, including 37signals,
            # that the non-blocking timeouts in 1.7.5 don't seem to be reliable.
            # It can't hurt to set the underlying socket timeout also, if possible.
            if timeout
              secs = Integer(timeout)
              usecs = Integer((timeout - secs) * 1_000_000)
              optval = [secs, usecs].pack("l_2")
              begin
                io.setsockopt Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, optval
                io.setsockopt Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, optval
              rescue Exception => ex
                # Solaris, for one, does not like/support socket timeouts.
                # 
              end
            end
            io
          end

          class BufferedIO < Net::BufferedIO # :nodoc:
            BUFSIZE = 1024 * 16

            if RUBY_VERSION < '1.9.1'
              def rbuf_fill
                begin
                  @rbuf << @io.read_nonblock(BUFSIZE)
                rescue Errno::EWOULDBLOCK
                  retry unless @read_timeout
                  if IO.select([@io], nil, nil, @read_timeout)
                    retry
                  else
                    raise Timeout::Error, 'IO timeout'
                  end
                end
              end
            end

            def setsockopt(*args)
              @io.setsockopt(*args)
            end

            def read
              read_all
            end
          end

      end
      
    end
  end
end
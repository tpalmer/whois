#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++

require 'whois/record/parser/whois.name.com.rb'

module Whois
  class Record
    class Parser
      # Parser for the whois.freestyleholdings.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisFreestyleholdingsCom < WhoisNameCom
      end
    end
  end
end

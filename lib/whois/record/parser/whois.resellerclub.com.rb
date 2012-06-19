#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++

require 'whois/record/parser/whois.publicdomainregistry.com.rb'

module Whois
  class Record
    class Parser
      # Parser for the whois.resellerclub.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisResellerclubCom < WhoisPublicdomainregistryCom
        property_supported :registrar do
          Record::Registrar.new(
            :name => "ResellerClub.com",
            :organization => "Directi Internet Solutions Pvt. Ltd.",
            :url  => "http://resellerclub.com"
          )
        end
      end
    end
  end
end

#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++

require 'whois/record/parser/base'

module Whois
  class Record
    class Parser
      # Parser for the whois.rrpproxy.net server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisRrpproxyNet < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_not_supported :created_on
        property_not_supported :updated_on
        property_not_supported :expires_on

        property_supported :registrar do
          Record::Registrar.new(
            :name => "domaindiscount24.com",
            :organization => "Key-Systems GmbH",
            :url  => "http://www.domaindiscount24.com"
          )
        end

        property_supported :registrant_contacts do
          build_contact('owner', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('admin', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('tech', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          content_match = content_for_scanner.match /(nameserver:\s+(.+)\n){1,}/
          return unless content_match

          content_match[0].lines.map do |line|
            line_match = line.match /nameserver:\s+((?<name>.+)\s+(?<ipv4>.+)|(?<name>.+))/

            Record::Nameserver.new(:name => line_match[:name], :ipv4 => line_match[:ipv4])
          end
        end

        private

        def build_contact(element, type)
          content_match = content_for_scanner.match /(#{element}-.+:\s+.+\n){1,}/
          return unless content_match

          attributes = { :type => type }

          content_match[0].lines.each do |line|
            line_match = line.match /#{element}-(?<key>.+):\s+(?<value>.+)/
            next unless line_match

            attributes[line_match['key'].to_sym] = line_match['value']
          end

          {
            :id => :contact,
            :name => [:fname, :lname, " "],
            :address => :street,
            :country_code => :country
          }.each do |key, source|
            if source.is_a? Array
              concatenation_string = source.pop
              attributes[key] = source.map { |source_key| attributes.delete source_key }.join(concatenation_string)
            else
              attributes[key] = attributes.delete source
            end
          end

          Record::Contact.new attributes
        end
      end
    end
  end
end


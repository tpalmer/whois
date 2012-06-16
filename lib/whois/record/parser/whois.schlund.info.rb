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
      # Parser for the whois.schlund.info server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisSchlundInfo < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_supported :created_on do
          if content_for_scanner =~ /created:\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /last-changed:\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /registration-expiration:\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "1&1",
            :organization => "1&1 Internet AG",
            :url  => "http://registrar.1und1.info"
          )
        end

        property_supported :registrant_contacts do
          build_contact('registrant', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('admin-c', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('tech-c', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          content_match = content_for_scanner.match /(nserver:\s+(.+)\n){1,}/
          return unless content_match

          content_match[0].lines.map do |line|
            line_match = line.match /nserver:\s+((?<name>.+)\s+(?<ipv4>.+)|(?<name>.+))/

            Record::Nameserver.new(:name => line_match[:name], :ipv4 => line_match[:ipv4])
          end
        end

        private

        def build_contact(element, type)
          # registrant-firstname:            Andreas
          # registrant-lastname:             Gauger
          # registrant-organization:         1&1 Internet Inc.
          # registrant-street1:              701 Lee Rd.
          # registrant-street2:              Suite 300
          # registrant-pcode:                19087
          # registrant-state:                PA
          # registrant-city:                 Chesterbrook
          # registrant-ccode:                US
          # registrant-phone:                +1.8774612631
          # registrant-fax:                  +1.6105601501
          # registrant-email:                hostmaster@oneandone.com

          content_match = content_for_scanner.match /(#{element}-.+:\s+.+\n){1,}/
          return unless content_match

          attributes = { :type => type }

          content_match[0].lines.each do |line|
            line_match = line.match /#{element}-(?<key>.+):\s+(?<value>.+)/
            next unless line_match

            attributes[line_match['key'].to_sym] = line_match['value']
          end

          {
            :name => [:firstname, :lastname, " "],
            :address => [:street1, :street2, "\n"],
            :country_code => :ccode,
            :zip => :pcode
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


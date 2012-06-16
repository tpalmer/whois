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
      # Parser for the whois.melbourneit.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisMelbourneitCom < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_supported :created_on do
          if content_for_scanner =~ /Creation Date\.+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Registration Date\.+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Expiry Date\.+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "Melbourne IT",
            :organization => "Melbourne IT Ltd",
            :url  => "http://melbourneit.com.au"
          )
        end

        property_supported :registrant_contacts do
          build_contact('Organisation', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('Admin', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Tech', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          content_match = content_for_scanner.match /(\s{2}Name Server\.+\s(.+)\n)+/
          return unless content_match

          content_match[0].lines.map do |line|
            line_match = line.match /Name Server\.+\s(?<name>.+)/

            Record::Nameserver.new(:name => line_match[:name])
          end
        end

        private

        def build_contact(element, type)
          attributes = { :type => type }

          address_match = content_for_scanner.match /(\s{2}#{element}\sAddress\.+(\s.+)?\n)+/
          return unless address_match 

          attribute_names = %w[address address city zip state country].map(&:to_sym)

          address_match[0].lines.each_with_index do |line, index|
            attribute = attribute_names[index]
            data = line.gsub(/\s{2}#{element}\sAddress\.+/, '').strip
            data = nil if data == ""

            if attributes[attribute]
              attributes[attribute] << "\n" << data if data
            else
              attributes[attribute] = data
            end
          end

          %w[Name Email Phone Fax].each do |attribute|
            attribute_match = content_for_scanner.match /#{element}\s#{attribute}\.+(?:(?:\n)|(?:\s(.+)))/
            next unless attribute_match

            attributes[attribute.downcase.to_sym] = attribute_match[1]
          end

          Record::Contact.new attributes
        end
      end
    end
  end
end


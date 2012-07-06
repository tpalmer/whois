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
      # Parser for the whois.name.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisNameCom < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_supported(:updated_on ) { nil }

        property_supported :created_on do
          if content_for_scanner =~ /Creation Date:\s+(.+)$/
            Time.parse $1
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Expiration Date:\s+(.+)$/
            Time.parse $1
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "Name.com",
            :organization => "Name.com LLC",
            :url  => "http://www.name.com"
          )
        end

        property_supported :registrant_contacts do
          build_contact 'REGISTRANT CONTACT INFO', Record::Contact::TYPE_REGISTRANT
        end

        property_supported :admin_contacts do
          build_contact 'ADMINISTRATIVE CONTACT INFO', Record::Contact::TYPE_ADMIN
        end

        property_supported :technical_contacts do
          build_contact 'TECHNICAL CONTACT INFO', Record::Contact::TYPE_TECHNICAL
        end

        property_supported :nameservers do
          content_match = content_for_scanner.match /Name\sServers:\n(?:(.+)\n)+/

          return unless content_match

          nameservers = content_match[0].split("\n")
          nameservers.shift

          return unless nameservers.any?

          nameservers.map do |line|
            Record::Nameserver.new :name => line.strip.downcase
          end
        end

        private

        def build_contact(element, type)
          content_match = content_for_scanner.match(/#{element}\n((.*)+|\n)+\n\n/)
          return unless content_match

          contact = content_match[0].lines.map(&:strip).keep_if { |line| line != element }.join("\n")

          match = contact.match(/
            (?<organization>.+)\n
            (?<name>.+)\n
            (?<address>(.|\n)+)\n
            (?<city>.+)\n
            (?<state>.+)\n
            (?<zip>.+)\n
            (?<country_code>\w{2})\n
            (Phone:\s*(?<phone>.+)\n)?
            (Fax:\s*(?<fax>.+)\n)?
            (Email\sAddress:\s*(?<email>.+))?
          /x)

          return unless match

          attributes = { :type => type }

          match.names.each do |name|
            attributes[name.to_sym] = match[name].strip if match[name]
          end

          Record::Contact.new attributes
        end
      end
    end
  end
end

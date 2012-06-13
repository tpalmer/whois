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
      # Parser for the whois.tucows.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisTucowsCom < Base
        property_supported :status do
          content_for_scanner =~ /Can't get information on non-local domain / ? :available : :registered
        end

        property_supported :available? do
          status == :available
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /Record created on\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Record last updated on\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Record expires on\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "Tucows",
            :organization => "Tucows, Inc.",
            :url  => "http://tucowsdomains.com"
          )
        end

        property_supported :registrant_contacts do
          build_contact('Registrant', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Contact', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Domain servers in listed order:\n((?:[^\n]+\n)+)/
            $1.split("\n").map do |line|
              name, ipv4 = line.strip.split(" ")
              Record::Nameserver.new(:name => name.downcase, :ipv4 => ipv4)
            end
          end
        end

        private

        def build_contact(element, type)
          # Registrant:
          #  Tucows.com Co
          #  96 Mowat Avenue
          #  Toronto, Ontario M6K3M1
          #  CA
          #
          #  Domain name: TUCOWS.COM
          #
          #
          #  Administrative Contact:
          #     Administrator, DNS  dnsadmin@tucows.com
          #     96 Mowat Avenue
          #     Toronto, Ontario M6K3M1
          #     CA
          #     +1.4165350123x0000
          #  Technical Contact:
          #     Administrator, DNS  dnsadmin@tucows.com
          #     96 Mowat Avenue
          #     Toronto, Ontario M6K3M1
          #     CA
          #     +1.4165350123x0000
          #
          #
          #  Registration Service Provider:
          #     Tucows.com Co., tucowsdomains@tucows.com
          #     416-535-0123

          contact = content_for_scanner.match(/#{element}\:\n((\s+.*){4,5})/)[1]

          return unless contact

          contact = contact.lines.map(&:strip).join("\n")

          match = contact.match(/
            (
              ((?<name>.+)\ {2}(?<email>.+@.+))|
              (?<organization>.+)
            )\n
            (?<address>(.|\n)+)\n
            (?<city>.+),\s(?<state>.+)\ (?<zip>.+)\n
            (?<country_code>.+)\n?
            (?<phone>.+)?\n?
          /x)

          return unless match

          attributes = { :type => type }

          match.names.each do |name|
            attributes[name.to_sym] = match[name]
          end

          Record::Contact.new attributes
        end
      end
    end
  end
end

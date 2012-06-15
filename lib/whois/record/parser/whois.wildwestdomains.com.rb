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
      # Parser for the whois.wildwestdomains.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisWildwestdomainsCom < Base
        property_supported :status do
          content_for_scanner =~ /No match for / ? :available : :registered
        end

        property_supported :available? do
          status == :available
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /Created on:\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Last Updated on:\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Expires on:\s+(.+)$/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "Wild West Domains",
            :organization => "Wild West Domains",
            :url  => "http://wwdomains.com"
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
              Record::Nameserver.new(:name => line.strip.downcase)
            end
          end
        end

        private

        def build_contact(element, type)
          # Registrant:
          #    Wild West Domains
          #    14455 N Hayden Rd Suite 219
          #    Scottsdale, Arizona 85260
          #    United States
          #
          #    Administrative Contact:
          #       Wild West Domains, Wild West Domains  dns@wildwestdomains.com
          #       Wild West Domains
          #       14455 N Hayden Rd Suite 219
          #       Scottsdale, Arizona 85260
          #       United States
          #       +1.4805058800      Fax -- +1.4805058844

          content_match = content_for_scanner.match(/#{element}\:\n((\s+.*){4,6})/)
          return unless content_match
          contact = content_match[1]
          return unless contact

          contact = contact.lines.map(&:strip).join("\n")

          match = contact.match(/
            ((?<name>.+)\ {2}(?<email>.+@.+))?\n?
            (?<organization>.+)\n
            (?<address>(.|\n)+)\n
            (?<city>.+),\s(?<state>.+)\ (?<zip>.+)\n
            (?<country>.+)\n?
            (
              (?<phone>.+)\s{6}Fax\ --\ (?<fax>.+)|
              (?<phone>.+)
            )?\n?
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


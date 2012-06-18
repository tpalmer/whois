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
      # Parser for the whois.register.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisRegisterCom < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_supported :created_on do
          if content_for_scanner =~ /Created on\.+:\s(.+)$/
            Time.parse($1)
          end
        end

        property_supported(:updated_on) { nil }

        property_supported :expires_on do
          if content_for_scanner =~ /Expires on\.+:\s(.+)$/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "Register.com",
            :organization => "Register.com",
            :url  => "http://register.com"
          )
        end

        property_supported :registrant_contacts do
          build_contact('Registrant', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical  Contact', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /DNS Servers:\n((?:[^\n]+\n)+)/
            $1.split("\n").map do |line|
              name = line.strip
              Record::Nameserver.new(:name => name.downcase)
            end
          end
        end

        private

        def build_contact(element, type)
          content_match = content_for_scanner.match(/#{element}\:\n((\s+.*){5,9})/)
          return unless content_match
          contact = content_match[1]
          return unless contact

          contact = contact.lines.map(&:strip).join("\n")

          match = contact.match(/
            (?<organization>.+)\n
            (?<name>.+)\n
            (?<address>(.|\n)+)\n
            (?<city>.+),\s(?<state>.+)\ (?<zip>.+)\n
            (?<country_code>.+)\n?
            (Phone:\s(?<phone>.+)\n)?
            (Fax:\s(?<fax>.+)\n)?
            (Email:\s(?<email>.+))?
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

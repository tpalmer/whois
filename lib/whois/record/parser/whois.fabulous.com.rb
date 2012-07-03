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
      # Parser for the whois.fabulous.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisFabulousCom < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_supported :created_on do
          if content_for_scanner =~ /Record created on: (.+)$/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Record modified on: (.+)$/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Record expires on: (.+)$/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "Fabulous.com",
            :organization => "Fabulous.com Pty Ltd",
            :url  => "http://www.fabulous.com"
          )
        end

        property_supported :registrant_contacts do
          build_contact(/Domain\s.+/, Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Info', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Nameservers:\n((?:[^\n]+\n)+)/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip.downcase)
            end
          end
        end

        private

        def build_contact(element, type)
          content_match = content_for_scanner.match(/#{element}:\n(?:(.+)(?:\n))+\n/)
          return unless content_match
          contact = content_match[0]
          return unless contact

          contact = contact.lines.map(&:strip).join("\n")

          match = contact.match(/
            .+\n
            (?<organization>.+)\n
            (?:(?<name>.+),\sCustomer\sID\s:\s(?<id>\d+)\n)?
            (?<email>.+@.+)?\n?
            (?<address>(.|\n)+)\n
            (?<city>[^,]+),?\s(?<state>.+)\s(?<zip>.+)\s(?<country_code>.+)\n
          /x)

          return unless match

          #attributes = { :type => type, :id => id }
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

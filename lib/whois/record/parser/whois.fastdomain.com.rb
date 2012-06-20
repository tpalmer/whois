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
      # Parser for the whois.fastdomain.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.me>
      #
      class WhoisFastdomainCom < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_supported :created_on do
          if content_for_scanner =~ /Created on\.+: (.+)$/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Last modified on\.+: (.+)$/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Expires on\.+: (.+)$/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "FastDomain",
            :organization => "FastDomain Inc.",
            :url  => "http://www.fastdomain.com"
          )
        end

        property_supported :registrant_contacts do
          build_contact('Registrant Info', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('Administrative Info', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Info', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Domain servers in listed order:\n\n((?:.|\n)+)\n\s+=-=-=-=/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip.downcase)
            end
          end
        end

        private

        def build_contact(element, type)
          content_match = content_for_scanner.match(/#{element}\:\s\((.+)\)\n((\s+.*){7,9})/)
          return unless content_match
          id, contact = content_match.captures
          return unless contact

          contact = contact.lines.map(&:strip).join("\n")

          match = contact.match(/
            (?<name>.+)\n
            (?<address>(.|\n)+)\n
            (?<city>.+),\s(?<state>.+) (?<zip>.+)\n
            (?<country>.+)\n
            Phone:\s(?<phone>.+)?\n?
            Fax\.\.:\s(?<fax>.+)?\n?
            Email:\s(?<email>.+)?
          /x)

          return unless match

          attributes = { :type => type, :id => id }

          match.names.each do |name|
            attributes[name.to_sym] = match[name].strip if match[name]
          end

          Record::Contact.new attributes
        end
      end
    end
  end
end

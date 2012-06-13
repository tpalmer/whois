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

      # Parser for the whois.moniker.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      class WhoisMonikerCom < Base
        property_supported :status do
          content_for_scanner =~ /No Match/ ? :available : :registered
        end

        property_supported :available? do
          status == :available
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /Record created on:\s*(.+)\.\d+$/
            Time.parse($1 << " UTC")
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Database last updated on:\s*(.+)\.\d$/
            Time.parse($1 << " UTC")
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Domain Expires on:\s*(.+)\.\d$/
            Time.parse($1 << " UTC")
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "Moniker",
            :organization => "Moniker Online Services LLC",
            :url  => "http://moniker.com"
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
          if content_for_scanner =~ /Domain servers in listed order:\n\n((?:[^\n]+\n)+)/
            $1.split("\n").map do |line|
              name, ipv4 = line.strip.split(" ")
              Record::Nameserver.new(:name => name.downcase, :ipv4 => ipv4)
            end
          end
        end

        private

        def build_contact(element, type)
          id, contact = content_for_scanner.match(/#{element}\s+\[(\d+)\]\:\n((.+\n){7,10})/).captures
          return unless contact

          # 0 Domain Manager domains@moniker.com
          # 1 Moniker Online Services, LLC
          # 2 20 SW 27th Ave.
          # 3 Suite 201
          # 4 Pompano Beach
          # 5 FL
          # 6 33069
          # 7 US
          # 8 Phone: +1.9549848445
          # 9 Fax:   +1.9549699155

          contact = contact.lines.map(&:strip).join("\n")

          match = contact.match(/
            (?<name>.+)\s(?<email>.+@.+)\n
            (?<organization>.+)\n
            (?<address>(.|\n)+)\n
            (?<city>.+)\n
            (?<state>.+)\n
            (?<zip>\d+)\n
            (?<country_code>.+)\n?
            (Phone:\s+(?<phone>.+))?\n?
            (Fax:\s+(?<fax>.+))?\n?
          /x)

          attributes = { :type => type, :id => id }

          match.names.each do |name|
            attributes[name.to_sym] = match[name]
          end

          Record::Contact.new attributes
        end

      end

    end
  end
end

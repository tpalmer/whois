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

      # Parser for the whois.onimae.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Justin Campbell <justin@cramerdev.com>
      #
      class WhoisOnimaeCom < Base
        property_supported(:status) { :registered }
        property_supported(:available?) { false }
        property_supported(:registered?) { true }

        property_supported :created_on do
          if content_for_scanner =~ /Created On: (.+)/
            Time.parse $1
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Last Updated On: (.+)/
            Time.parse $1
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Expiration Date: (.+)/
            Time.parse $1
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => "GMO Internet",
            :organization => "GMO Internet, Inc.",
            :url  => "http://onimae.com"
          )
        end

        property_supported :registrant_contacts do
          build_contact 'Registrant', Record::Contact::TYPE_REGISTRANT
        end

        property_supported :admin_contacts do
          build_contact 'Admin', Record::Contact::TYPE_ADMIN
        end

        property_supported :technical_contacts do
          build_contact 'Tech', Record::Contact::TYPE_TECHNICAL
        end


        property_supported :nameservers do
          content_match = content_for_scanner.match /(?:\n?Name Server: (.+))+/
          return unless content_match

          nameservers = content_match[0].strip.split("\n").map { |line| line.gsub "Name Server: ", "" }

          nameservers.map { |nameserver| Record::Nameserver.new :name => nameserver }
        end

        private

       def build_contact(element, type)
          content_match = content_for_scanner.match /(#{element}\s.+:\s+.+\n)+/
          return unless content_match

          attributes = { :type => type }

          content_match[0].lines.each do |line|
            line_match = line.match /#{element}\s(?<key>.+):\s+(?<value>.+)/
            next unless line_match

            attributes[line_match['key'].downcase.to_sym] = line_match['value']
          end

          {
            :address => [:street1, :street2, "\n"],
            :country_code => :country,
            :zip => :'postal code'
          }.each do |key, source|
            if source.is_a? Array
              concatenation_string = source.pop
              attributes[key] = source.map { |source_key| attributes.delete source_key }.compact.join(concatenation_string)
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


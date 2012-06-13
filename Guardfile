guard 'rspec', :version => 2 do
  watch(%r{^lib/whois/record/parser/(.+)\.rb$}) { |match| Dir["spec/whois/record/parser/responses/#{match[1]}/*"] }

  watch(%r{^spec/.+_spec\.rb$})
  watch('spec/spec_helper.rb')  { "spec" }
end


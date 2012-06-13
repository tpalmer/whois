source "http://rubygems.org"

# Specify your gem's dependencies in whois.gemspec
gemspec

group :development do
  gem 'rspec'

  group :guard do
    gem 'guard-rspec'

    group :darwin do
      gem 'growl'
      gem 'rb-fsevent'
    end
  end
end

require_relative 'boot'

require 'rails/all'

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

require 'dotenv'
Dotenv.load

module ThriveBigcommerceDev
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 6.0

    # Set tmp ngrok tunnel as host.
    config.hosts << "d9acf68f20e4.ngrok.io"

    # Settings in config/environments/* take precedence over those specified here.
    # Application configuration can go into files in config/initializers
    # -- all .rb files in that directory are automatically loaded after loading
    # the framework and any gems in your application.

    # Set up CORS allow for just the info gather route. 
    config.middleware.insert_before 0, Rack::Cors do
      allow do
        origins '*'
        resource '/gather', :headers => :any, :methods => [:get, :post, :options]
      end
    end
    
  end
end

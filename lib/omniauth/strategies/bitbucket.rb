require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Bitbucket < OmniAuth::Strategies::OAuth2
      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        :site => 'https://bitbucket.org',
        :authorize_url     => 'https://bitbucket.org/site/oauth2/authorize',
        :token_url  => 'https://bitbucket.org/site/oauth2/access_token'
      }

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid { raw_info['username'] }

      info do
        {
          :name => "#{raw_info['first_name']} #{raw_info['last_name']}",
          :avatar => raw_info['avatar'],
          :email => raw_info['email']
        }
      end

      def raw_info
        @raw_info ||= begin
                        ri = MultiJson.decode(access_token.get('/api/1.0/user').body)['user']
                        email = MultiJson.decode(access_token.get('/api/1.0/emails').body).find { |email| email['primary'] }
                        ri.merge!('email' => email['email']) if email
                        ri
                      end
      end

    protected

      # overrides OmniAuth::Strategies::OAuth2 to prevent using the full
      # callback_url which includes the query_string that makes bitbucket throw
      # us an error since it's not exactly identical to the configured
      # redirect_uri.
      def build_access_token
        verifier = request.params["code"]
        # like OmniAuth::Strategy#callback_url but without query string
        callback_url = full_host + script_name + callback_path
        client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

    end
  end
end

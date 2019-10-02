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
                        ri = MultiJson.decode(access_token.get('/api/2.0/user').body)['user']
                        email = MultiJson.decode(access_token.get('/api/2.0/emails').body).find { |email| email['primary'] }
                        ri.merge!('email' => email['email']) if email
                        ri
                      end
      end

    protected

      # overrides OmniAuth::Strategies::OAuth2 to prevent using the full
      # callback_url which includes the query_string that makes bitbucket throw
      # us an error since it's not exactly identical to the previously used
      # redirect_uri, which at most includes the login_hint parameter.
      def build_access_token
        verifier = request.params["code"]
        # remove code and state URL params from OmniAuth::Strategy#callback_url
        redirect_uri = URI(callback_url)
        params = Hash[URI.decode_www_form(String(redirect_uri.query))]
        params.delete 'code'
        params.delete 'state'
        redirect_uri.query = params.empty? ? nil : URI.encode_www_form(params.to_a)
        client.auth_code.get_token(verifier, {:redirect_uri => redirect_uri.to_s}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

    end
  end
end

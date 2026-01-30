require "oauth2"
require "omniauth"
require "securerandom"
require "socket"       # for SocketError
require "timeout"      # for Timeout::Error

module OmniAuth
  module Strategies
    # Authentication strategy for connecting with APIs constructed using
    # the [OAuth 2.0 Specification](http://tools.ietf.org/html/draft-ietf-oauth-v2-10).
    # You must generally register your application with the provider and
    # utilize an application id and secret in order to authenticate using
    # OAuth 2.0.
    class OAuth2
      include OmniAuth::Strategy

      def self.inherited(subclass)
        OmniAuth::Strategy.included(subclass)
      end

      args %i[client_id client_secret]

      option :client_id, nil
      option :client_secret, nil
      option :client_options, {}
      option :authorize_params, {}
      option :authorize_options, %i[scope state]
      option :token_params, {}
      option :token_options, []
      option :auth_token_params, {}
      option :provider_ignores_state, false
      option :pkce, false
      option :pkce_verifier, nil
      option :pkce_options, {
        :code_challenge => proc { |verifier|
          Base64.urlsafe_encode64(
            Digest::SHA2.digest(verifier),
            :padding => false,
          )
        },
        :code_challenge_method => "S256",
      }

      attr_accessor :access_token

      def client
        ::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      credentials do
        hash = {"token" => access_token.token}
        hash["refresh_token"] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash["expires_at"] = access_token.expires_at if access_token.expires?
        hash["expires"] = access_token.expires?
        hash
      end

      def request_phase
        redirect client.auth_code.authorize_url({:redirect_uri => callback_url}.merge(authorize_params))
      end

      def authorize_params # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        options.authorize_params[:state] = SecureRandom.hex(24)

        if OmniAuth.config.test_mode
          @env ||= {}
          @env["rack.session"] ||= {}
        end

        params = options.authorize_params
                        .merge(options_for("authorize"))
                        .merge(pkce_authorize_params)

        metadata = {}
        metadata["pkce_verifier"] = options.pkce_verifier if options.pkce
        store_state(params[:state], metadata)

        params
      end

      def token_params
        options.token_params.merge(options_for("token")).merge(pkce_token_params)
      end

      def callback_phase # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        error = request.params["error_reason"] || request.params["error"]
        if !options.provider_ignores_state && (request.params["state"].to_s.empty? || !valid_state?(request.params["state"]))
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
        elsif error
          fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
        else
          self.access_token = build_access_token
          self.access_token = access_token.refresh! if access_token.expired?
          cleanup_expired_state
          super
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT, ::OAuth2::TimeoutError, ::OAuth2::ConnectionError => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

    protected

      def migrate_legacy_session
        return unless session.key?("omniauth.state")
        old_state = session.delete("omniauth.state")
        old_verifier = session.delete("omniauth.pkce.verifier")

        return unless old_state

        session["omniauth.oauth2_states"] ||= {}
        session["omniauth.oauth2_states"][old_state] = {"iat" => Time.now.to_i, "exp" => nil}
        session["omniauth.oauth2_states"][old_state]["pkce_verifier"] = old_verifier if old_verifier
      end

      def store_state(state, metadata = {})
        migrate_legacy_session
        session["omniauth.oauth2_states"] ||= {}
        session["omniauth.oauth2_states"][state] = metadata.merge("iat" => Time.now.to_i, "exp" => nil)
      end

      def find_state(state)
        session["omniauth.oauth2_states"] ||= {}

        session["omniauth.oauth2_states"].each_pair do |stored_state, metadata|
          if secure_compare(state, stored_state)
            return [stored_state, metadata]
          end
        end

        nil
      end

      def valid_state?(state)
        migrate_legacy_session
        found = find_state(state)

        return false unless found

        stored_state, metadata = found

        return false if metadata["exp"]

        session["omniauth.oauth2_states"][stored_state]["exp"] = Time.now.to_i

        true
      end

      def get_state_metadata(state)
        found = find_state(state)
        found ? found[1] : nil
      end

      def cleanup_expired_state
        session["omniauth.oauth2_states"] ||= {}
        session["omniauth.oauth2_states"].delete_if do |_state, metadata|
          metadata["exp"]
        end
      end

      def pkce_authorize_params
        return {} unless options.pkce

        options.pkce_verifier = SecureRandom.hex(64)

        # NOTE: see https://tools.ietf.org/html/rfc7636#appendix-A
        {
          :code_challenge => options.pkce_options[:code_challenge]
                                    .call(options.pkce_verifier),
          :code_challenge_method => options.pkce_options[:code_challenge_method],
        }
      end

      def pkce_token_params
        return {} unless options.pkce

        state = request.params["state"]
        metadata = get_state_metadata(state)
        verifier = metadata && metadata["pkce_verifier"]

        {:code_verifier => verifier}
      end

      def build_access_token
        verifier = request.params["code"]
        client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

      def deep_symbolize(options)
        options.each_with_object({}) do |(key, value), hash|
          hash[key.to_sym] = value.is_a?(Hash) ? deep_symbolize(value) : value
        end
      end

      def options_for(option)
        hash = {}
        options.send(:"#{option}_options").select { |key| options[key] }.each do |key|
          hash[key.to_sym] = if options[key].respond_to?(:call)
                               options[key].call(env)
                             else
                               options[key]
                             end
        end
        hash
      end

       # constant-time comparison algorithm to prevent timing attacks
       def secure_compare(string_a, string_b)
        return false unless string_a.bytesize == string_b.bytesize

        l = string_a.unpack "C#{string_a.bytesize}"

        res = 0
        string_b.each_byte { |byte| res |= byte ^ l.shift }
        res.zero?
      end

      # An error that is indicated in the OAuth 2.0 callback.
      # This could be a `redirect_uri_mismatch` or other
      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(" | ")
        end
      end
    end
  end
end

OmniAuth.config.add_camelization "oauth2", "OAuth2"

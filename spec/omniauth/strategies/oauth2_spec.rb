require "helper"

describe OmniAuth::Strategies::OAuth2 do
  def app
    lambda do |_env|
      [200, {}, ["Hello."]]
    end
  end
  let(:fresh_strategy) { Class.new(OmniAuth::Strategies::OAuth2) }

  before do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  describe "Subclassing Behavior" do
    subject { fresh_strategy }

    it "performs the OmniAuth::Strategy included hook" do
      expect(OmniAuth.strategies).to include(OmniAuth::Strategies::OAuth2)
      expect(OmniAuth.strategies).to include(subject)
    end
  end

  describe "#client" do
    subject { fresh_strategy }

    it "is initialized with symbolized client_options" do
      instance = subject.new(app, :client_options => {"authorize_url" => "https://example.com"})
      expect(instance.client.options[:authorize_url]).to eq("https://example.com")
    end

    it "sets ssl options as connection options" do
      instance = subject.new(app, :client_options => {"ssl" => {"ca_path" => "foo"}})
      expect(instance.client.options[:connection_opts][:ssl]).to eq(:ca_path => "foo")
    end
  end

  describe "#authorize_params" do
    subject { fresh_strategy }

    it "includes any authorize params passed in the :authorize_params option" do
      instance = subject.new("abc", "def", :authorize_params => {:foo => "bar", :baz => "zip"})
      expect(instance.authorize_params["foo"]).to eq("bar")
      expect(instance.authorize_params["baz"]).to eq("zip")
    end

    it "includes top-level options that are marked as :authorize_options" do
      instance = subject.new("abc", "def", :authorize_options => %i[scope foo state], :scope => "bar", :foo => "baz")
      expect(instance.authorize_params["scope"]).to eq("bar")
      expect(instance.authorize_params["foo"]).to eq("baz")
      expect(instance.authorize_params["state"]).not_to be_empty
    end

    it "includes random state in the authorize params" do
      instance = subject.new("abc", "def")
      expect(instance.authorize_params.keys).to eq(["state"])
      state = instance.authorize_params["state"]
      expect(instance.session["omniauth.oauth2_states"]).to have_key(state)
    end

    it "includes custom state in the authorize params" do
      instance = subject.new("abc", "def", :state => proc { "qux" })
      expect(instance.authorize_params.keys).to eq(["state"])
      expect(instance.session["omniauth.oauth2_states"]).to have_key("qux")
    end

    it "supports multiple concurrent states" do
      instance = subject.new("abc", "def")
      state1 = instance.authorize_params["state"]
      state2 = instance.authorize_params["state"]
      state3 = instance.authorize_params["state"]
      expect(instance.session["omniauth.oauth2_states"].keys).to match_array([state1, state2, state3])
    end

    it "migrates old single state to states hash" do
      instance = subject.new("abc", "def")
      instance.authorize_params
      instance.session["omniauth.state"] = "old_state"
      instance.session.delete("omniauth.oauth2_states")
      new_state = instance.authorize_params["state"]
      expect(instance.session["omniauth.oauth2_states"].keys).to match_array(["old_state", new_state])
      expect(instance.session["omniauth.state"]).to be_nil
    end

    it "includes PKCE parameters if enabled" do
      instance = subject.new("abc", "def", :pkce => true)
      params = instance.authorize_params
      expect(params[:code_challenge]).to be_a(String)
      expect(params[:code_challenge_method]).to eq("S256")
      state = params["state"]
      expect(instance.session["omniauth.oauth2_states"][state]["pkce_verifier"]).to be_a(String)
    end
  end

  describe "#token_params" do
    subject { fresh_strategy }

    it "includes any authorize params passed in the :authorize_params option" do
      instance = subject.new("abc", "def", :token_params => {:foo => "bar", :baz => "zip"})
      expect(instance.token_params).to eq("foo" => "bar", "baz" => "zip")
    end

    it "includes top-level options that are marked as :authorize_options" do
      instance = subject.new("abc", "def", :token_options => %i[scope foo], :scope => "bar", :foo => "baz")
      expect(instance.token_params).to eq("scope" => "bar", "foo" => "baz")
    end

    it "includes the PKCE code_verifier if enabled" do
      instance = subject.new("abc", "def", :pkce => true)
      params = instance.authorize_params
      state = params["state"]
      allow(instance).to receive(:request).and_return(double("Request", :params => {"state" => state}))
      expect(instance.token_params[:code_verifier]).to be_a(String)
    end
  end

  describe "#callback_phase" do
    subject(:instance) { fresh_strategy.new("abc", "def") }

    let(:params) { {"error_reason" => "user_denied", "error" => "access_denied", "state" => state} }
    let(:state) { "secret" }

    before do
      allow(instance).to receive(:request) do
        double("Request", :params => params)
      end
    end

    context "with new states hash format" do
      it "calls fail with the error received" do
        session = {"omniauth.oauth2_states" => {state => {"iat" => Time.now.to_i, "exp" => nil}}}
        allow(instance).to receive(:session).and_return(session)
        expect(instance).to receive(:fail!).with("user_denied", anything)
        instance.callback_phase
      end

      it "marks the validated state as expired" do
        session = {"omniauth.oauth2_states" => {
          state => {"iat" => Time.now.to_i, "exp" => nil},
          "other_state" => {"iat" => Time.now.to_i, "exp" => nil}
        }}
        allow(instance).to receive(:session).and_return(session)
        expect(instance).to receive(:fail!).with("user_denied", anything)
        instance.callback_phase
        expect(session["omniauth.oauth2_states"][state]["exp"]).not_to be_nil
        expect(session["omniauth.oauth2_states"]["other_state"]["exp"]).to be_nil
      end
    end

    context "with legacy single state format" do
      it "calls fail with the error received" do
        session = {"omniauth.state" => state}
        allow(instance).to receive(:session).and_return(session)
        expect(instance).to receive(:fail!).with("user_denied", anything)
        instance.callback_phase
      end

      it "removes the old state key after validation" do
        session = {"omniauth.state" => state}
        allow(instance).to receive(:session).and_return(session)
        expect(instance).to receive(:fail!).with("user_denied", anything)
        instance.callback_phase
        expect(session).not_to have_key("omniauth.state")
      end
    end

    it "calls fail with the error received if state is missing and CSRF verification is disabled" do
      params["state"] = nil
      instance.options.provider_ignores_state = true
      allow(instance).to receive(:session).and_return({})

      expect(instance).to receive(:fail!).with("user_denied", anything)

      instance.callback_phase
    end

    it "calls fail with a CSRF error if the state is missing" do
      params["state"] = nil
      allow(instance).to receive(:session).and_return({})

      expect(instance).to receive(:fail!).with(:csrf_detected, anything)
      instance.callback_phase
    end

    it "calls fail with a CSRF error if the state is invalid" do
      params["state"] = "invalid"
      allow(instance).to receive(:session).and_return({"omniauth.oauth2_states" => {state => {"iat" => Time.now.to_i, "exp" => nil}}})

      expect(instance).to receive(:fail!).with(:csrf_detected, anything)
      instance.callback_phase
    end

    it "validates concurrent states correctly" do
      state1 = "state1"
      state2 = "state2"
      state3 = "state3"
      params["state"] = state2
      session = {"omniauth.oauth2_states" => {
        state1 => {"iat" => Time.now.to_i, "exp" => nil},
        state2 => {"iat" => Time.now.to_i, "exp" => nil},
        state3 => {"iat" => Time.now.to_i, "exp" => nil}
      }}
      allow(instance).to receive(:session).and_return(session)

      expect(instance).to receive(:fail!).with("user_denied", anything)
      instance.callback_phase
      expect(session["omniauth.oauth2_states"][state2]["exp"]).not_to be_nil
      expect(session["omniauth.oauth2_states"][state1]["exp"]).to be_nil
      expect(session["omniauth.oauth2_states"][state3]["exp"]).to be_nil
    end

    it "prevents replay attacks by rejecting already-used states" do
      params["state"] = state
      session = {"omniauth.oauth2_states" => {
        state => {"iat" => Time.now.to_i, "exp" => Time.now.to_i - 60}
      }}
      allow(instance).to receive(:session).and_return(session)

      expect(instance).to receive(:fail!).with(:csrf_detected, anything)
      instance.callback_phase
    end

    it "cleans up all states with exp set" do
      state1 = "state1"
      state2 = "state2"
      state3 = "state3"
      session = {"omniauth.oauth2_states" => {
        state1 => {"iat" => Time.now.to_i, "exp" => Time.now.to_i},
        state2 => {"iat" => Time.now.to_i, "exp" => Time.now.to_i - 60},
        state3 => {"iat" => Time.now.to_i, "exp" => nil}
      }}
      allow(instance).to receive(:session).and_return(session)

      instance.send(:cleanup_expired_state)

      expect(session["omniauth.oauth2_states"]).not_to have_key(state1)
      expect(session["omniauth.oauth2_states"]).not_to have_key(state2)
      expect(session["omniauth.oauth2_states"]).to have_key(state3)
    end

    describe 'exception handlings' do
      let(:params) do
        {"code" => "code", "state" => state}
      end

      before do
        allow(instance).to receive(:session).and_return({"omniauth.oauth2_states" => {state => {"iat" => Time.now.to_i, "exp" => nil}}})
        allow_any_instance_of(OmniAuth::Strategies::OAuth2).to receive(:build_access_token).and_raise(exception)
      end

      {
        :invalid_credentials => [OAuth2::Error, OmniAuth::Strategies::OAuth2::CallbackError],
        :timeout => [Timeout::Error, Errno::ETIMEDOUT, OAuth2::TimeoutError, OAuth2::ConnectionError],
        :failed_to_connect => [SocketError]
      }.each do |error_type, exceptions|
        exceptions.each do |klass|
          context "when #{klass}" do
            let(:exception) { klass.new 'error' }

            it do
              expect(instance).to receive(:fail!).with(error_type, exception)
              instance.callback_phase
            end
          end
        end
      end
    end
  end

  describe "#secure_compare" do
    subject { fresh_strategy }

    it "returns true when the two inputs are the same and false otherwise" do
      instance = subject.new("abc", "def")
      expect(instance.send(:secure_compare, "a", "a")).to be true
      expect(instance.send(:secure_compare, "b", "a")).to be false
    end
  end
end

describe OmniAuth::Strategies::OAuth2::CallbackError do
  let(:error) { Class.new(OmniAuth::Strategies::OAuth2::CallbackError) }
  describe "#message" do
    subject { error }
    it "includes all of the attributes" do
      instance = subject.new("error", "description", "uri")
      expect(instance.message).to match(/error/)
      expect(instance.message).to match(/description/)
      expect(instance.message).to match(/uri/)
    end
    it "includes all of the attributes" do
      instance = subject.new(nil, :symbol)
      expect(instance.message).to eq("symbol")
    end
  end
end

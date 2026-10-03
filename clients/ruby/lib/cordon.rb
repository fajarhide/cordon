# frozen_string_literal: true

# The cordon client. It builds requests and reads answers, and holds no rule of
# its own: a rule implemented twice is a rule that drifts, so every decision
# about what a path means belongs to the daemon.
#
# Apache 2.0, unlike the AGPL daemon, so linking this into a closed source
# application is fine.

require "json"
require "net/http"
require "uri"

module Cordon
  # Every refusal, with the daemon's stable code so a caller branches on that
  # rather than on the message.
  class Error < StandardError
    attr_reader :code, :status

    def initialize(code, message, status)
      super(message)
      @code = code
      @status = status
    end
  end

  class Client
    # transport is anything that answers call(method, url, headers, body) with
    # [status, body]. It exists so a test does not need a socket.
    def initialize(base, token: nil, transport: nil)
      @base = base
      @token = token
      @transport = transport || method(:http)
    end

    # Call this before touching a file on an owner's behalf.
    def resolve(owner, path, inherit: false)
      post("/v1/resolve", owner: owner, path: path, inherit: inherit)
    end

    # Takes the request as keywords: owner:, entrypoint:, and optionally args:,
    # stdin:, collect:, inherit:, network:, hosts:, backend:, limits:.
    def run(owner:, entrypoint:, **rest)
      post("/v1/run", { owner: owner, entrypoint: entrypoint }.merge(rest))
    end

    def fork(from, to)
      post("/v1/fork", from: from, to: to)
    end

    # The owner is required. A token alone is not enough, deliberately: it is
    # bound to one owner on the daemon and omitting the owner used to skip the
    # check rather than fail it.
    def artifact(token, owner)
      q = URI.encode_www_form_component(owner.join("/"))
      status, body = @transport.call(:get, "#{@base}/v1/artifact/#{token}?owner=#{q}", headers, nil)
      raise Error.new("artifact_not_found", "no such artifact", status) unless ok?(status)

      body
    end

    private

    def post(path, payload)
      status, body = @transport.call(:post, @base + path, headers, JSON.generate(payload))

      # A gateway in front of the daemon can answer with HTML, so the body is
      # never assumed to be JSON.
      parsed = begin
        JSON.parse(body.to_s)
      rescue JSON::ParserError
        nil
      end
      return parsed if ok?(status)

      e = parsed.is_a?(Hash) && parsed["error"].is_a?(Hash) ? parsed["error"] : {}
      raise Error.new(e["code"] || "unknown", e["message"] || "HTTP #{status}", status)
    end

    def ok?(status)
      (200..299).cover?(status)
    end

    def headers
      h = { "content-type" => "application/json" }
      h["authorization"] = "Bearer #{@token}" if @token
      h
    end

    def http(method, url, headers, body)
      uri = URI(url)
      req = (method == :post ? Net::HTTP::Post : Net::HTTP::Get).new(uri, headers)
      req.body = body if body
      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |h| h.request(req) }
      [res.code.to_i, res.body.to_s]
    end
  end
end

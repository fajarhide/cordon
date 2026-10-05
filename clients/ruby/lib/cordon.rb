# frozen_string_literal: true

# Builds requests and reads answers. Every rule lives in the daemon, so it cannot drift.
# Apache 2.0, unlike the AGPL daemon.

require "json"
require "net/http"
require "uri"

module Cordon
  # Carries the daemon's stable code, so a caller branches on that and not on the message.
  class Error < StandardError
    attr_reader :code, :status

    def initialize(code, message, status)
      super(message)
      @code = code
      @status = status
    end
  end

  class Client
    # transport answers call(method, url, headers, body) with [status, body]. Tests inject one.
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

    # Operator token only. Without ttl_seconds the token lasts until it is revoked.
    def issue_token(prefix, ttl_seconds: nil)
      payload = { prefix: prefix }
      payload[:ttl_seconds] = ttl_seconds if ttl_seconds
      post("/v1/token", payload)
    end

    # Operator token only.
    def revoke_token(token)
      send_json(:delete, "/v1/token/#{token}", nil)
      nil
    end

    # The owner is required: a token is bound to one owner on the daemon (#8).
    def artifact(token, owner)
      q = URI.encode_www_form_component(owner.join("/"))
      status, body = @transport.call(:get, "#{@base}/v1/artifact/#{token}?owner=#{q}", headers, nil)
      raise Error.new("artifact_not_found", "no such artifact", status) unless ok?(status)

      body
    end

    private

    def post(path, payload)
      send_json(:post, path, JSON.generate(payload))
    end

    def send_json(method, path, payload)
      status, body = @transport.call(method, @base + path, headers, payload)

      # A gateway in front of the daemon can answer with HTML, so the body may not be JSON.
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
      req = Net::HTTP.const_get(method.to_s.capitalize).new(uri, headers)
      req.body = body if body
      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |h| h.request(req) }
      [res.code.to_i, res.body.to_s]
    end
  end
end

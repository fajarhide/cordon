# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/cordon"

# The same cases as clients/typescript/src/index.test.ts, so the two clients
# cannot quietly disagree about what goes on the wire.
class CordonTest < Minitest::Test
  # A client whose transport records every call and answers with one response.
  def client(status = 200, body = "{}", token: nil)
    @calls = []
    Cordon::Client.new("http://x", token: token, transport: lambda { |method, url, headers, payload|
      @calls << { method: method, url: url, headers: headers, body: payload && JSON.parse(payload) }
      [status, body]
    })
  end

  def test_resolve_sends_the_owner_the_path_and_an_explicit_inherit
    out = client(200, '{"resolved":"/w/a.md","exists":true}').resolve(%w[acme budi], "a.md")

    assert_equal "http://x/v1/resolve", @calls[0][:url]
    assert_equal({ "owner" => %w[acme budi], "path" => "a.md", "inherit" => false }, @calls[0][:body])
    assert_equal "/w/a.md", out["resolved"]
    assert_equal true, out["exists"]
  end

  def test_a_refusal_becomes_a_typed_error_carrying_the_code_and_the_status
    c = client(403, '{"error":{"code":"path_escapes_workspace","message":"no"}}')
    err = assert_raises(Cordon::Error) { c.resolve(%w[acme budi], "../ani/x") }

    assert_equal "path_escapes_workspace", err.code
    assert_equal 403, err.status
    assert_equal "no", err.message
  end

  def test_run_sends_the_request_and_returns_the_artifacts
    c = client(200, '{"exit_code":0,"network":"open","artifacts":[{"token":"art_abc","path":"out/r.txt","bytes":2}]}')
    res = c.run(owner: %w[acme budi], entrypoint: "true", network: "open",
                hosts: { "litellm.internal" => "10.0.0.5" })

    assert_equal "http://x/v1/run", @calls[0][:url]
    assert_equal "open", @calls[0][:body]["network"]
    assert_equal({ "litellm.internal" => "10.0.0.5" }, @calls[0][:body]["hosts"])
    assert_equal "art_abc", res["artifacts"][0]["token"]
    # And the response says what it got, rather than echoing what was asked.
    assert_equal "open", res["network"]
  end

  def test_artifact_returns_the_bytes_and_sends_the_owner_url_encoded
    bytes = client(200, "hi").artifact("art_abc", %w[acme legal budi])

    assert_equal "hi", bytes
    assert_equal :get, @calls[0][:method]
    # Encoded, so a segment cannot smuggle a separator.
    assert_equal "http://x/v1/artifact/art_abc?owner=acme%2Flegal%2Fbudi", @calls[0][:url]
  end

  # The daemon has required the owner since issue #8. A client that made it
  # optional would put the caller back where that issue started.
  def test_artifact_cannot_be_called_without_an_owner
    assert_raises(ArgumentError) { client.artifact("art_abc") }
  end

  def test_a_refused_artifact_is_an_error_not_a_body
    c = client(404, '{"error":{"code":"artifact_not_found","message":"no such artifact"}}')
    err = assert_raises(Cordon::Error) { c.artifact("art_abc", %w[acme ani]) }

    assert_equal "artifact_not_found", err.code
    assert_equal 404, err.status
  end

  def test_a_non_json_error_body_still_produces_an_error_not_a_parse_crash
    err = assert_raises(Cordon::Error) { client(502, "<html>502</html>").resolve(%w[acme budi], "a.md") }

    assert_equal 502, err.status
    assert_equal "unknown", err.code
  end

  def test_a_token_is_sent_when_one_is_configured
    client(200, "{}", token: "s3cret").resolve(%w[a], "b")
    assert_equal "Bearer s3cret", @calls[0][:headers]["authorization"]
  end

  def test_no_token_means_no_authorization_header
    client.resolve(%w[a], "b")
    refute @calls[0][:headers].key?("authorization")
  end

  def test_fork_passes_both_owners
    out = client(200, '{"forked":"acme/copy","skipped_links":0}').fork(%w[acme budi], %w[acme copy])

    assert_equal({ "from" => %w[acme budi], "to" => %w[acme copy] }, @calls[0][:body])
    assert_equal "acme/copy", out["forked"]
  end
end

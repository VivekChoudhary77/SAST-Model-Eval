from triage.sanitize import Sanitizer, ast_signature, count_comments, shape_like

SRC = '''/**
 * OWASP Benchmark Project v1.2 licence header
 */
package org.owasp.benchmark.testcode;

@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {
    public void doPost() {
        String url = "http://example.com//path"; // trailing comment
        String param = request.getHeader("BenchmarkTest00008");
        // Simple if statement that assigns constant to bar on true condition
        String bar = "This should never happen";
        String other = "This should never happen";
        String keep = "/* not a comment */";
        java.util.Properties benchmarkprops = new java.util.Properties();
        String alg = benchmarkprops.getProperty("hashAlg1", "SHA512");
        org.owasp.benchmark.helpers.ThingInterface t = null;
        String user = "SafeDonna";
    }
}
'''


def run():
    return Sanitizer({"00008": "4117"}).sanitize(SRC)


def test_comments_removed_and_lines_kept():
    res = run()
    assert count_comments(res.text) == 0
    assert res.text.count("\n") == SRC.count("\n")
    assert "Simple if statement" not in res.text and "OWASP" not in res.text


def test_comment_markers_inside_strings_survive():
    res = run()
    assert '"http://example.com//path"' in res.text
    assert '"/* not a comment */"' in res.text


def test_identity_renamed_consistently():
    text = run().text
    assert "BenchmarkTest" not in text and "benchmark" not in text.lower()
    assert "public class Handler4117" in text
    assert 'getHeader("Handler4117")' in text
    assert '@WebServlet(value = "/api/handler4117")' in text
    assert "package com.acmepay.app.web;" in text
    assert "com.acmepay.app.util.ThingInterface" in text
    assert "appProps.getProperty" in text


def test_hint_literals_neutralised_consistently_per_file():
    text = run().text
    assert "never" not in text and "Safe" not in text
    token = shape_like("v1", "This should never happen")
    assert text.count(f'"{token}"') == 2  # same literal -> same token
    assert '"digest.alg.b"' in text and "hashAlg1" not in text
    assert '"SHA512"' in text  # algorithm names are never touched


def test_shape_like_preserves_length_and_separators():
    assert shape_like("v1", " SafeStuff") == " v1xxxxxxx"
    assert shape_like("v12", "safe!") == "v12x!"


def test_ast_shape_unchanged():
    assert ast_signature(SRC) == ast_signature(run().text)

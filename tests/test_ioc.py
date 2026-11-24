from threatlens.ioc import classify, defang, extract, refang


def test_refang_and_classify():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert classify("8.8.8[.]8").type == "ipv4"
    assert classify("2001:db8::1").type == "ipv6"
    assert classify("Example.COM").value == "example.com"
    assert classify("d41d8cd98f00b204e9800998ecf8427e").type == "md5"
    assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").type == "sha256"
    assert classify("not an indicator") is None


def test_defang_roundtrip():
    assert defang("http://a.b/c") == "hxxp://a[.]b/c"
    assert refang(defang("http://a.b/c")) == "http://a.b/c"


def test_extract_from_text():
    text = """Phish sent from 203.0.113.9, link hxxp://login-paypa1[.]com/verify,
    dropper sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and C2 bad-c2[.]xyz."""
    got = {(i.type, i.value) for i in extract(text)}
    assert ("ipv4", "203.0.113.9") in got
    assert ("url", "http://login-paypa1.com/verify") in got
    assert ("domain", "bad-c2.xyz") in got
    assert ("domain", "login-paypa1.com") not in got  # already covered by the URL
    assert any(t == "sha256" for t, _ in got)

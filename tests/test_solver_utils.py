import json
from app.solver import (
    encrypt_payload,
    get_fp,
    build_crc_table,
    calculate_crc,
    encode_number,
    encode_fp,
    build_everything,
    _check,
    sha256_hashcash,
    compute_pow,
    compute_bandwidth,
    get_filter_bytes,
    ALPHABET,
    IEEE_POLYNOMIAL,
)


class TestEncryptPayload:
    def test_returns_three_parts(self):
        result = encrypt_payload("hello")
        parts = result.split("::")
        assert len(parts) == 3

    def test_iv_is_base64(self):
        import base64
        result = encrypt_payload("test")
        iv_b64 = result.split("::")[0]
        decoded = base64.b64decode(iv_b64)
        assert len(decoded) == 12

    def test_different_calls_produce_different_iv(self):
        r1 = encrypt_payload("same")
        r2 = encrypt_payload("same")
        assert r1 != r2  # random IV


class TestGetFp:
    def test_returns_dict_with_required_keys(self):
        ua = "TestAgent/1.0"
        fp = get_fp(ua)
        assert fp["userAgent"] == ua
        assert "metrics" in fp
        assert "start" in fp
        assert "end" in fp
        assert "version" in fp
        assert fp["version"] == "2.4.0"

    def test_start_less_than_end(self):
        fp = get_fp("TestAgent/1.0")
        assert fp["start"] <= fp["end"]

    def test_canvas_histogram_length(self):
        fp = get_fp("TestAgent/1.0")
        assert len(fp["canvas"]["histogramBins"]) == 256


class TestCrc:
    def test_crc_table_length(self):
        table = build_crc_table()
        assert len(table) == 256

    def test_crc_table_with_default_polynomial(self):
        table = build_crc_table(IEEE_POLYNOMIAL)
        assert table[0] == 0

    def test_calculate_crc_deterministic(self):
        table = build_crc_table()
        r1 = calculate_crc("hello", table)
        r2 = calculate_crc("hello", table)
        assert r1 == r2

    def test_different_inputs_different_crc(self):
        table = build_crc_table()
        r1 = calculate_crc("hello", table)
        r2 = calculate_crc("world", table)
        assert r1 != r2


class TestEncodeNumber:
    def test_returns_8_char_hex(self):
        result = encode_number(12345)
        assert len(result) == 8
        assert all(c in ALPHABET.upper() for c in result)

    def test_zero(self):
        result = encode_number(0)
        assert result == "00000000"

    def test_max_32bit(self):
        result = encode_number(0xFFFFFFFF)
        assert result == "FFFFFFFF"


class TestEncodeFp:
    def test_returns_tuple(self):
        encoded, checksum = encode_fp("TestAgent/1.0")
        assert isinstance(encoded, str)
        assert isinstance(checksum, str)
        assert "#" in encoded
        assert encoded.startswith(checksum + "#")

    def test_payload_is_valid_json(self):
        encoded, _ = encode_fp("TestAgent/1.0")
        json_str = encoded.split("#", 1)[1]
        data = json.loads(json_str)
        assert data["userAgent"] == "TestAgent/1.0"


class TestBuildEverything:
    def test_has_required_keys(self):
        result = build_everything("TestAgent/1.0")
        assert "checksum" in result
        assert "encoded" in result
        assert "encrypted" in result

    def test_encrypted_format(self):
        result = build_everything("TestAgent/1.0")
        parts = result["encrypted"].split("::")
        assert len(parts) == 3


class TestCheck:
    def test_easy_difficulty(self):
        assert _check(0, "ff") is True

    def test_difficulty_1_pass(self):
        assert _check(1, "0f") is True

    def test_difficulty_1_fail(self):
        assert _check(1, "ff") is False


class TestSha256Hashcash:
    def test_deterministic(self):
        r1 = sha256_hashcash("test")
        r2 = sha256_hashcash("test")
        assert r1 == r2

    def test_returns_hex_string(self):
        result = sha256_hashcash("test")
        assert len(result) == 64
        int(result, 16)  # should not raise


class TestComputePow:
    def test_finds_nonce(self):
        nonce = compute_pow("test", "CHECK", 1)
        assert nonce is not None
        assert int(nonce) >= 0


class TestComputeBandwidth:
    def test_returns_base64(self):
        import base64
        result = compute_bandwidth("", "", 1)
        decoded = base64.b64decode(result)
        assert len(decoded) == 1024

    def test_difficulty_levels(self):
        import base64
        for diff, expected_size in [(1, 1024), (2, 10240), (3, 102400)]:
            result = compute_bandwidth("", "", diff)
            decoded = base64.b64decode(result)
            assert len(decoded) == expected_size


class TestGetFilterBytes:
    def test_known_values(self):
        assert get_filter_bytes(1) == 1024
        assert get_filter_bytes(2) == 10 * 1024
        assert get_filter_bytes(3) == 100 * 1024
        assert get_filter_bytes(4) == 1 * 1048576
        assert get_filter_bytes(5) == 10 * 1048576

    def test_unknown_returns_zero(self):
        assert get_filter_bytes(99) == 0

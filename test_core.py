import json, os, subprocess, sys, tempfile, textwrap, unittest, time
import core

SECRET = "super-secret-value-for-tests"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


class TestCrypto(unittest.TestCase):
    def test_roundtrip(self):
        t = core.encrypt_payload({"vid": "x", "n": 1}, SECRET)
        self.assertEqual(core.decrypt_payload(t, SECRET), {"vid": "x", "n": 1})

    def test_wrong_secret_and_tamper(self):
        t = core.encrypt_payload({"a": 1}, SECRET)
        self.assertIsNone(core.decrypt_payload(t, "other"))
        raw = bytearray(core._b64url_decode(t)); raw[-1] ^= 1
        self.assertIsNone(core.decrypt_payload(core._b64url_encode(bytes(raw)), SECRET))
        self.assertIsNone(core.decrypt_payload("garbage!!", SECRET))
        self.assertIsNone(core.decrypt_payload("", SECRET))

    def test_interop_with_nextjs_streamtoken(self):
        """Mints a token with the REAL lib/streamToken.ts (transpiled),
        decrypts it here; and the reverse direction via node:crypto."""
        tsc = subprocess.run(["which", "tsc"], capture_output=True, text=True).stdout.strip()
        if not tsc:
            self.skipTest("tsc not available")
        out = tempfile.mkdtemp()
        src_copy = os.path.join(out, "streamToken.ts")
        with open(os.path.join(REPO, "lib/streamToken.ts")) as f:
            open(src_copy, "w").write(f.read())
        r0 = subprocess.run([tsc, "--outDir", out, "--module", "commonjs", "--target", "es2020",
                        "--skipLibCheck", src_copy],
                       capture_output=True, text=True, cwd=out)
        js = os.path.join(out, "streamToken.js")
        if not os.path.exists(js):
            self.skipTest("could not transpile streamToken.ts")
        # stub `server-only`
        os.makedirs(os.path.join(out, "node_modules/server-only"), exist_ok=True)
        open(os.path.join(out, "node_modules/server-only/index.js"), "w").write("")
        script = textwrap.dedent(f"""
            process.env.STREAM_TOKEN_SECRET = {json.dumps(SECRET)};
            const m = require({json.dumps(js)});
            const payload = {{vid:"11111111-1111-1111-1111-111111111111",uid:"u",ip:m.hashForToken("1.2.3.4"),
                             aid:"a",exp:Math.floor(Date.now()/1000)+20,sr:"c/1234567890/45",rh:null}};
            console.log(JSON.stringify({{token:m.createStreamToken(payload),payload,iph:m.hashForToken("1.2.3.4")}}));
        """)
        r = subprocess.run(["node", "-e", script], capture_output=True, text=True, cwd=out)
        self.assertEqual(r.returncode, 0, r.stderr)
        j = json.loads(r.stdout)
        self.assertEqual(core.decrypt_payload(j["token"], SECRET), j["payload"])
        self.assertEqual(core.hash_for_token("1.2.3.4"), j["iph"])

        # python -> node direction (sid blobs are only read by Python, but
        # proves the wire format is symmetric)
        py_tok = core.encrypt_payload({"hello": "world"}, SECRET)
        script2 = textwrap.dedent(f"""
            const {{createDecipheriv, createHash}} = require('node:crypto');
            const raw = Buffer.from({json.dumps(py_tok)}, 'base64url');
            const d = createDecipheriv('aes-256-gcm', createHash('sha256').update({json.dumps(SECRET)}).digest(), raw.subarray(0,12));
            d.setAuthTag(raw.subarray(12,28));
            console.log(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString());
        """)
        r2 = subprocess.run(["node", "-e", script2], capture_output=True, text=True)
        self.assertEqual(json.loads(r2.stdout), {"hello": "world"})


class TestSourceRef(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(core.parse_source_ref("c/1234567890/45"), core.SourceRef("private", 1234567890, 45))
        self.assertEqual(core.parse_source_ref("my_channel/9"), core.SourceRef("public", "my_channel", 9))

    def test_forum_topic_links(self):
        # https://t.me/c/4408902778/2/3 -> group 4408902778, topic 2, message 3
        self.assertEqual(core.parse_source_ref("c/4408902778/2/3"), core.SourceRef("private", 4408902778, 3, 2))
        self.assertEqual(core.parse_source_ref("c/4408902778/2/3").msg_id, 3)
        self.assertEqual(core.parse_source_ref("my_group/5/77"), core.SourceRef("public", "my_group", 77, 5))

    def test_bad(self):
        for bad in ["", "c/12/3", "c/abc/1", "a/1", "x y/1", "chan/-1", "chan/1/2/3/4", "c/1234567890/1/2/3", "../etc/1", "http://t.me/a/1"]:
            self.assertIsNone(core.parse_source_ref(bad), bad)


class TestRange(unittest.TestCase):
    def test_cases(self):
        S = 1000
        self.assertIsNone(core.parse_range(None, S))
        self.assertEqual(core.parse_range("bytes=0-", S), (0, 999))
        self.assertEqual(core.parse_range("bytes=10-19", S), (10, 19))
        self.assertEqual(core.parse_range("bytes=990-5000", S), (990, 999))
        self.assertEqual(core.parse_range("bytes=-100", S), (900, 999))
        self.assertEqual(core.parse_range("bytes=-5000", S), (0, 999))
        for bad in ["bytes=1000-", "bytes=20-10", "bytes=-", "bytes=0-1,5-6", "items=0-1", "bytes=-0"]:
            with self.assertRaises(core.RangeNotSatisfiable, msg=bad):
                core.parse_range(bad, S)


class TestIp(unittest.TestCase):
    def test_cases(self):
        # the proxy appended 1.2.3.4; the left entry is whatever the client claimed
        self.assertEqual(core.client_ip("6.6.6.6, 1.2.3.4", "10.0.0.1", 1), "1.2.3.4")
        self.assertEqual(core.client_ip("6.6.6.6, 7.7.7.7, 1.2.3.4", "10.0.0.1", 2), "7.7.7.7")
        self.assertEqual(core.client_ip("1.2.3.4", "10.0.0.1", 1), "1.2.3.4")
        self.assertEqual(core.client_ip(None, "10.0.0.1", 1), "10.0.0.1")
        self.assertEqual(core.client_ip("1.2.3.4", "10.0.0.1", 0), "10.0.0.1")  # no trusted proxy -> ignore XFF
        self.assertEqual(core.client_ip("not-an-ip", "10.0.0.1", 1), "10.0.0.1")

    def test_edge_set_header_wins_and_is_validated(self):
        self.assertEqual(core.client_ip("6.6.6.6, 9.9.9.9", "10.0.0.1", 1, preferred="1.2.3.4"), "1.2.3.4")
        self.assertEqual(core.client_ip("6.6.6.6, 9.9.9.9", "10.0.0.1", 1, preferred="junk"), "9.9.9.9")
        self.assertEqual(core.client_ip(None, "10.0.0.1", 1, preferred="2001:db8::1"), "2001:db8::1")


class TestCache(unittest.TestCase):
    def test_lru(self):
        c = core.ChunkCache(10)
        c.put("a", b"1234"); c.put("b", b"1234"); c.get("a"); c.put("c", b"1234")
        self.assertIsNone(c.get("b")); self.assertEqual(c.get("a"), b"1234"); self.assertLessEqual(c.size, 10)
        c.put("big", b"x" * 11); self.assertIsNone(c.get("big"))


class TestSessions(unittest.TestCase):
    def test_lifecycle(self):
        s = core.SessionStore(ttl=90)
        st = s.register("j", "iphash", now=1000)
        self.assertEqual(st.exp, 1090)
        s.register("j", "newip", now=1050)  # renewal + re-bind
        self.assertEqual((s.get("j").exp, s.get("j").ip), (1140, "newip"))
        self.assertEqual(s.purge(now=1100), 0)
        self.assertEqual(s.purge(now=2000), 1)
        self.assertEqual(len(s), 0)


class TestSessionHardening(unittest.TestCase):
    def test_ip_changes_counted_and_drop(self):
        s = core.SessionStore(ttl=100)
        st = s.register("j", "A", now=1000)
        self.assertEqual((st.born, st.ip_changes), (1000, 0))
        s.register("j", "A", now=1010)
        self.assertEqual(st.ip_changes, 0)
        s.register("j", "B", now=1020)
        s.register("j", "A", now=1030)
        self.assertEqual(st.ip_changes, 2)
        self.assertEqual(st.born, 1000)  # absolute age never slides
        s.drop("j")
        self.assertIsNone(s.get("j"))


class TestViewerLimiter(unittest.TestCase):
    def setUp(self):
        self.L = core.ViewerLimiter(max_conns=4, day_factor=6, rate_factor=3, burst_seconds=120, min_rate=0.5 * core.MB, min_burst=32 * core.MB)
        self.size = 1100 * core.MB
        self.dur = 95 * 60  # ~1.93 MB/s bitrate, like the real class video

    def test_params(self):
        rate, cap = self.L.params(self.size, self.dur)
        self.assertAlmostEqual(rate / core.MB, 1100 / 5700 * 3, places=2)
        self.assertGreaterEqual(cap, 32 * core.MB)
        self.assertIsNone(self.L.params(self.size, None))
        self.assertIsNone(self.L.params(self.size, 0))

    def test_normal_playback_never_waits(self):
        p = self.L.params(self.size, self.dur)
        st = self.L.get(("u", "v"), p[1], now=0)
        # real-time playback at ~bitrate, pulled in 1MB chunks, plus a seek burst of 40MB
        t = 0.0
        waited = 0.0
        for _ in range(600):
            t += 5.0  # 1MB every 5s = ~0.2MB/s, the video's real bitrate
            waited += self.L.take(st, core.MB, self.size, p, now=t)
        for _ in range(40):
            waited += self.L.take(st, core.MB, self.size, p, now=t)
        self.assertEqual(waited, 0.0)

    def test_bulk_download_is_slowed_to_a_multiple_of_playtime(self):
        p = self.L.params(self.size, self.dur)
        st = self.L.get(("u", "v"), p[1], now=0)
        t = 0.0
        for _ in range(1100):  # a download manager grabbing the whole file as fast as it can
            t += self.L.take(st, core.MB, self.size, p, now=t)
        self.assertGreater(t, self.dur / 3 * 0.8)  # >= ~1/3 of the video's own duration
        self.assertLess(t, self.dur / 3 * 1.2)

    def test_daily_cap(self):
        size = 100 * core.MB
        p = self.L.params(size, 3600)
        st = self.L.get(("u", "v"), p[1], now=0)
        sent = 0
        with self.assertRaises(core.DailyLimitExceeded):
            while True:
                self.L.take(st, core.MB, size, p, now=0)
                sent += 1
        self.assertEqual(sent, 600)  # 6 x 100MB
        self.assertFalse(self.L.day_over(st, size, now=90000))  # window resets after 24h

    def test_unknown_duration_not_throttled_but_capped(self):
        st = self.L.get(("u", "v"), 0, now=0)
        self.assertEqual(self.L.take(st, core.MB, 10 * core.MB, None, now=0), 0.0)


if __name__ == "__main__":
    unittest.main()

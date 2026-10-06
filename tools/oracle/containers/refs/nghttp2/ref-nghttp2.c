/*
 * The nghttp2 reference: libnghttp2's HTTP/2 server session and its HPACK
 * encoder and decoder.
 *
 * Same protocol as the other reference drivers: tab-separated cases on stdin
 * (id, kind, split, arg, hex), one `id split json` line out, every string
 * hex. kind h2 is a server session fed the client's bytes; hd decodes one
 * HPACK block with nghttp2_hd_inflate_*; he encodes a field blob with
 * nghttp2_hd_deflate_*. Every case gets a line.
 *
 * Options. nghttp2_option is NOT used at all: every option is at its
 * default, which means header validation and HTTP messaging checks
 * (nghttp2's no_http_messaging off) stay ON. That is where pseudo-header
 * order and presence, upper-case names, connection-specific fields, TE other
 * than "trailers" and content-length against the body are enforced.
 * Automatic WINDOW_UPDATE is also left on, so a client sending more than the
 * 65535-octet window in one go is not necessarily a flow-control violation
 * here: the session consumes the data and credits it back as it goes. That
 * is what an application that reads its body does, and is reported as seen.
 *
 * Settings submitted: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=65535,
 * MAX_FRAME_SIZE=16384, HEADER_TABLE_SIZE=4096, MAX_HEADER_LIST_SIZE=65536.
 * ENABLE_PUSH is a client-only setting and is not sent; nghttp2 refuses a
 * PUSH_PROMISE received by a server on its own.
 *
 * The application never answers a request. The session's output is drained
 * after every receive call and parsed afterwards as frames: RST_STREAM on a
 * stream and GOAWAY with an error code are what resets and conn_error report.
 * A bad client magic makes nghttp2_session_mem_recv2 return an error WITHOUT
 * queueing a GOAWAY (it just stops), so conn_error stays null there and the
 * error text says so; the integrator should treat that as nghttp2's refusal.
 *
 * Streams live in a fixed table of 512; a stream beyond that is ignored and
 * said so in err.
 *
 * hd: nghttp2's decoder has one fixed cap this driver cannot raise, a name
 * plus value of more than 65536 octets (NGHTTP2_HD_MAX_NV) is an error. The
 * decoder's table size comes from change_table_size, which sets the limit the
 * peer may signal; the table itself starts at the library default of 4096
 * and is shrunk when arg is smaller.
 */
#define _GNU_SOURCE
#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- growable byte buffer ---- */

typedef struct {
  uint8_t *p;
  size_t n, cap;
} buf_t;

static void *xrealloc(void *p, size_t n) {
  void *r = realloc(p, n ? n : 1);
  if (!r) {
    fputs("out of memory\n", stderr);
    exit(70);
  }
  return r;
}

static void buf_add(buf_t *b, const void *d, size_t n) {
  if (b->n + n > b->cap) {
    size_t c = b->cap ? b->cap : 64;
    while (c < b->n + n) c *= 2;
    b->p = xrealloc(b->p, c);
    b->cap = c;
  }
  if (n) memcpy(b->p + b->n, d, n);
  b->n += n;
}

static void buf_free(buf_t *b) {
  free(b->p);
  b->p = NULL;
  b->n = b->cap = 0;
}

static void buf_str(buf_t *b, const char *s) { buf_add(b, s, strlen(s)); }

static void buf_hex(buf_t *b, const uint8_t *d, size_t n) {
  static const char H[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    char c[2] = {H[d[i] >> 4], H[d[i] & 15]};
    buf_add(b, c, 2);
  }
}

static void buf_printf(buf_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#include <stdarg.h>
static void buf_printf(buf_t *b, const char *fmt, ...) {
  char t[256];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(t, sizeof t, fmt, ap);
  va_end(ap);
  if (n > 0) buf_add(b, t, (size_t)n < sizeof t ? (size_t)n : sizeof t - 1);
}

/* A JSON string for free text: plain ASCII, escaped. */
static void buf_jstr(buf_t *b, const char *s) {
  buf_str(b, "\"");
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      char e[2] = {'\\', (char)c};
      buf_add(b, e, 2);
    } else if (c < 0x20 || c >= 0x7f) {
      buf_printf(b, "\\u%04x", c);
    } else {
      buf_add(b, &c, 1);
    }
  }
  buf_str(b, "\"");
}

static int unhex(const char *s, size_t n, buf_t *out) {
  if (n % 2) return -1;
  for (size_t i = 0; i < n; i += 2) {
    int v[2];
    for (int k = 0; k < 2; k++) {
      char c = s[i + k];
      v[k] = c >= '0' && c <= '9' ? c - '0'
             : c >= 'a' && c <= 'f' ? c - 'a' + 10
             : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
      if (v[k] < 0) return -1;
    }
    uint8_t byte = (uint8_t)(v[0] << 4 | v[1]);
    buf_add(out, &byte, 1);
  }
  return 0;
}

/* ---- header lists ---- */

typedef struct {
  buf_t name, value;
} field_t;

typedef struct {
  field_t *f;
  size_t n, cap;
} list_t;

static void list_add(list_t *l, const uint8_t *n, size_t nl, const uint8_t *v, size_t vl) {
  if (l->n == l->cap) {
    l->cap = l->cap ? l->cap * 2 : 8;
    l->f = xrealloc(l->f, l->cap * sizeof *l->f);
  }
  field_t *f = &l->f[l->n++];
  memset(f, 0, sizeof *f);
  buf_add(&f->name, n, nl);
  buf_add(&f->value, v, vl);
}

static void list_clear(list_t *l) {
  for (size_t i = 0; i < l->n; i++) {
    buf_free(&l->f[i].name);
    buf_free(&l->f[i].value);
  }
  l->n = 0;
}

static void list_free(list_t *l) {
  list_clear(l);
  free(l->f);
  memset(l, 0, sizeof *l);
}

static void list_json(buf_t *o, const list_t *l) {
  buf_str(o, "[");
  for (size_t i = 0; i < l->n; i++) {
    if (i) buf_str(o, ",");
    buf_str(o, "[\"");
    buf_hex(o, l->f[i].name.p, l->f[i].name.n);
    buf_str(o, "\",\"");
    buf_hex(o, l->f[i].value.p, l->f[i].value.n);
    buf_str(o, "\"]");
  }
  buf_str(o, "]");
}

/* ---- h2 ---- */

#define MAXS 512

typedef struct {
  int32_t stream;
  buf_t method, scheme, authority, path;
  int has_method, has_scheme, has_authority, has_path;
  list_t headers, trailers, pending;
  buf_t pmethod, pscheme, pauthority, ppath;
  int phas[4];
  buf_t body;
  int ended;
  int open_msg; /* the request section was accepted */
  int used;
  int order; /* delivery order, 1-based, 0 = none */
} strm_t;

typedef struct {
  strm_t s[MAXS];
  int nused;
  int norder;
  char err[256];
  int overflow;
} ctx_t;

static void note(ctx_t *c, const char *what) {
  if (c->err[0]) return;
  snprintf(c->err, sizeof c->err, "%s", what);
}

static strm_t *find(ctx_t *c, int32_t id, int create) {
  for (int i = 0; i < c->nused; i++)
    if (c->s[i].stream == id) return &c->s[i];
  if (!create) return NULL;
  if (c->nused == MAXS) {
    if (!c->overflow) note(c, "stream table full, later streams ignored");
    c->overflow = 1;
    return NULL;
  }
  strm_t *s = &c->s[c->nused++];
  memset(s, 0, sizeof *s);
  s->stream = id;
  return s;
}

static void pending_reset(strm_t *s) {
  list_clear(&s->pending);
  buf_free(&s->pmethod);
  buf_free(&s->pscheme);
  buf_free(&s->pauthority);
  buf_free(&s->ppath);
  memset(s->phas, 0, sizeof s->phas);
}

static int on_begin_headers(nghttp2_session *ses, const nghttp2_frame *frame, void *ud) {
  (void)ses;
  ctx_t *c = ud;
  if (frame->hd.type != NGHTTP2_HEADERS) return 0;
  strm_t *s = find(c, frame->hd.stream_id, 1);
  if (s) pending_reset(s);
  return 0;
}

static int on_header(nghttp2_session *ses, const nghttp2_frame *frame, const uint8_t *name,
                     size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                     void *ud) {
  (void)ses;
  (void)flags;
  ctx_t *c = ud;
  if (frame->hd.type != NGHTTP2_HEADERS) return 0;
  strm_t *s = find(c, frame->hd.stream_id, 0);
  if (!s) return 0;
  if (namelen && name[0] == ':') {
    struct {
      const char *n;
      buf_t *b;
      int *h;
    } t[4] = {{":method", &s->pmethod, &s->phas[0]},
              {":scheme", &s->pscheme, &s->phas[1]},
              {":authority", &s->pauthority, &s->phas[2]},
              {":path", &s->ppath, &s->phas[3]}};
    for (int i = 0; i < 4; i++) {
      if (strlen(t[i].n) == namelen && !memcmp(t[i].n, name, namelen)) {
        /* nghttp2 refuses a repeated pseudo-header before getting here; if
         * one ever arrives, the later one wins and the oddity is noted. */
        if (*t[i].h) {
          note(c, "repeated pseudo-header reached the application");
          buf_free(t[i].b);
        }
        buf_add(t[i].b, value, valuelen);
        *t[i].h = 1;
        return 0;
      }
    }
    note(c, "unknown pseudo-header reached the application");
    list_add(&s->pending, name, namelen, value, valuelen);
    return 0;
  }
  list_add(&s->pending, name, namelen, value, valuelen);
  return 0;
}

static void take(buf_t *dst, int *has, buf_t *src, int phas) {
  *dst = *src;
  memset(src, 0, sizeof *src);
  *has = phas;
}

static int on_frame_recv(nghttp2_session *ses, const nghttp2_frame *frame, void *ud) {
  (void)ses;
  ctx_t *c = ud;
  int32_t id = frame->hd.stream_id;
  if (frame->hd.type == NGHTTP2_HEADERS) {
    strm_t *s = find(c, id, 0);
    if (!s) return 0;
    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST && !s->open_msg) {
      s->open_msg = 1;
      s->order = ++c->norder;
      take(&s->method, &s->has_method, &s->pmethod, s->phas[0]);
      take(&s->scheme, &s->has_scheme, &s->pscheme, s->phas[1]);
      take(&s->authority, &s->has_authority, &s->pauthority, s->phas[2]);
      take(&s->path, &s->has_path, &s->ppath, s->phas[3]);
      s->headers = s->pending;
      memset(&s->pending, 0, sizeof s->pending);
    } else if (s->open_msg && frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
      list_free(&s->trailers);
      s->trailers = s->pending;
      memset(&s->pending, 0, sizeof s->pending);
    } else if (s->open_msg) {
      note(c, "unexpected HEADERS category after the request");
    }
    if (s->open_msg && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) s->ended = 1;
  } else if (frame->hd.type == NGHTTP2_DATA) {
    strm_t *s = find(c, id, 0);
    if (s && s->open_msg && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) s->ended = 1;
  }
  return 0;
}

static int on_data_chunk(nghttp2_session *ses, uint8_t flags, int32_t id, const uint8_t *data,
                         size_t len, void *ud) {
  (void)ses;
  (void)flags;
  ctx_t *c = ud;
  strm_t *s = find(c, id, 0);
  if (s && s->open_msg) buf_add(&s->body, data, len);
  return 0;
}

static int on_invalid_frame_recv(nghttp2_session *ses, const nghttp2_frame *frame,
                                 int lib_error_code, void *ud) {
  (void)ses;
  ctx_t *c = ud;
  char t[200];
  snprintf(t, sizeof t, "invalid frame type %d on stream %d: %s", frame->hd.type,
           (int)frame->hd.stream_id, nghttp2_strerror(lib_error_code));
  note(c, t);
  return 0;
}

/* Returning 0 leaves nghttp2's own reaction in place: it resets the stream. */
static int on_invalid_header(nghttp2_session *ses, const nghttp2_frame *frame,
                             const uint8_t *name, size_t namelen, const uint8_t *value,
                             size_t valuelen, uint8_t flags, void *ud) {
  (void)ses;
  (void)value;
  (void)valuelen;
  (void)flags;
  ctx_t *c = ud;
  char t[200];
  snprintf(t, sizeof t, "invalid header on stream %d: %.*s", (int)frame->hd.stream_id,
           (int)(namelen > 60 ? 60 : namelen), (const char *)name);
  note(c, t);
  return 0;
}

/* Drain what the session wants to write into `out`. */
static void pump(nghttp2_session *ses, buf_t *out) {
  for (;;) {
    const uint8_t *d;
    nghttp2_ssize n = nghttp2_session_mem_send2(ses, &d);
    if (n <= 0) break;
    buf_add(out, d, (size_t)n);
  }
}

static void run_h2(const buf_t *in, int byte, buf_t *res) {
  ctx_t *c = calloc(1, sizeof *c);
  if (!c) exit(70);
  buf_t out = {0};

  nghttp2_session_callbacks *cb;
  nghttp2_session_callbacks_new(&cb);
  nghttp2_session_callbacks_set_on_begin_headers_callback(cb, on_begin_headers);
  nghttp2_session_callbacks_set_on_header_callback(cb, on_header);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_data_chunk);
  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cb, on_invalid_frame_recv);
  nghttp2_session_callbacks_set_on_invalid_header_callback(cb, on_invalid_header);

  /* The session said the connection is dead (mem_recv failed): a refusal that
   * sends no GOAWAY, which conn_error cannot show. */
  int closed = 0;
  nghttp2_session *ses = NULL;
  int rv = nghttp2_session_server_new(&ses, cb, c);
  nghttp2_session_callbacks_del(cb);
  if (rv) {
    note(c, "session_server_new failed");
  } else {
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 16384},
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 65536},
    };
    rv = nghttp2_submit_settings(ses, NGHTTP2_FLAG_NONE, iv, sizeof iv / sizeof *iv);
    if (rv) note(c, nghttp2_strerror(rv));
    pump(ses, &out);

    size_t off = 0;
    while (off < in->n) {
      size_t take_n = byte ? 1 : in->n - off;
      nghttp2_ssize r = nghttp2_session_mem_recv2(ses, in->p + off, take_n);
      if (r < 0) {
        closed = 1;
        char t[200];
        snprintf(t, sizeof t, "mem_recv: %s", nghttp2_strerror((int)r));
        note(c, t);
        pump(ses, &out);
        break; /* the session says the connection is dead */
      }
      off += take_n; /* mem_recv consumes it all unless it errs */
      pump(ses, &out);
      if (!nghttp2_session_want_read(ses) && !nghttp2_session_want_write(ses)) break;
    }
    nghttp2_session_del(ses);
  }

  /* Frames the implementation wrote. */
  buf_t resets = {0};
  int conn_error = -1;
  size_t nres = 0;
  for (size_t i = 0; i + 9 <= out.n;) {
    const uint8_t *h = out.p + i;
    size_t len = (size_t)h[0] << 16 | (size_t)h[1] << 8 | h[2];
    uint8_t type = h[3];
    uint32_t sid = (uint32_t)(h[5] & 0x7f) << 24 | (uint32_t)h[6] << 16 | (uint32_t)h[7] << 8 | h[8];
    if (i + 9 + len > out.n) break;
    const uint8_t *p = h + 9;
    if (type == 3 && sid != 0 && len >= 4) {
      uint32_t code = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
      buf_printf(&resets, "%s[%u,%u]", nres++ ? "," : "", sid, code);
    } else if (type == 7 && len >= 8 && conn_error < 0) {
      uint32_t code = (uint32_t)p[4] << 24 | (uint32_t)p[5] << 16 | (uint32_t)p[6] << 8 | p[7];
      if (code) conn_error = (int)code;
    }
    i += 9 + len;
  }

  buf_str(res, "{\"msgs\":[");
  int first = 1;
  for (int o = 1; o <= c->norder; o++) {
    for (int i = 0; i < c->nused; i++) {
      strm_t *s = &c->s[i];
      if (s->order != o) continue;
      if (!first) buf_str(res, ",");
      first = 0;
      buf_printf(res, "{\"stream\":%d", (int)s->stream);
      struct {
        const char *k;
        buf_t *b;
        int h;
      } t[4] = {{"method", &s->method, s->has_method},
                {"scheme", &s->scheme, s->has_scheme},
                {"authority", &s->authority, s->has_authority},
                {"path", &s->path, s->has_path}};
      for (int k = 0; k < 4; k++) {
        buf_printf(res, ",\"%s\":", t[k].k);
        if (t[k].h) {
          buf_str(res, "\"");
          buf_hex(res, t[k].b->p, t[k].b->n);
          buf_str(res, "\"");
        } else {
          buf_str(res, "null");
        }
      }
      buf_str(res, ",\"headers\":");
      list_json(res, &s->headers);
      buf_str(res, ",\"body\":\"");
      buf_hex(res, s->body.p, s->body.n);
      buf_str(res, "\",\"trailers\":");
      list_json(res, &s->trailers);
      buf_printf(res, ",\"ended\":%s}", s->ended ? "true" : "false");
    }
  }
  buf_str(res, "],\"resets\":[");
  buf_add(res, resets.p, resets.n);
  buf_str(res, "],\"conn_error\":");
  if (conn_error < 0) buf_str(res, "null");
  else buf_printf(res, "%d", conn_error);
  buf_str(res, closed ? ",\"closed\":true" : ",\"closed\":false");
  buf_str(res, ",\"err\":");
  buf_jstr(res, c->err);
  buf_str(res, "}");

  for (int i = 0; i < c->nused; i++) {
    strm_t *s = &c->s[i];
    buf_free(&s->method);
    buf_free(&s->scheme);
    buf_free(&s->authority);
    buf_free(&s->path);
    list_free(&s->headers);
    list_free(&s->trailers);
    pending_reset(s);
    list_free(&s->pending);
    buf_free(&s->body);
  }
  buf_free(&resets);
  buf_free(&out);
  free(c);
}

/* ---- hd ---- */

static void run_hd(const buf_t *in, size_t table, buf_t *res) {
  nghttp2_hd_inflater *inf;
  list_t l = {0};
  int error = 0;
  char err[200] = "";
  if (nghttp2_hd_inflate_new(&inf)) {
    buf_str(res, "{\"list\":[],\"error\":true,\"err\":\"inflate_new failed\"}");
    return;
  }
  nghttp2_hd_inflate_change_table_size(inf, table);

  const uint8_t *p = in->p;
  size_t left = in->n;
  int done = 0;
  for (;;) {
    nghttp2_nv nv;
    int flags = 0;
    nghttp2_ssize r = nghttp2_hd_inflate_hd3(inf, &nv, &flags, p, left, 1);
    if (r < 0) {
      error = 1;
      snprintf(err, sizeof err, "inflate_hd3: %s", nghttp2_strerror((int)r));
      break;
    }
    p += r;
    left -= (size_t)r;
    if (flags & NGHTTP2_HD_INFLATE_EMIT) list_add(&l, nv.name, nv.namelen, nv.value, nv.valuelen);
    if (flags & NGHTTP2_HD_INFLATE_FINAL) {
      nghttp2_hd_inflate_end_headers(inf);
      done = 1;
      break;
    }
    if (!(flags & NGHTTP2_HD_INFLATE_EMIT) && left == 0) break;
  }
  if (!error && !done) {
    error = 1;
    snprintf(err, sizeof err, "block not finished");
  }
  buf_str(res, "{\"list\":");
  list_json(res, &l);
  buf_printf(res, ",\"error\":%s,\"err\":", error ? "true" : "false");
  buf_jstr(res, err);
  buf_str(res, "}");
  list_free(&l);
  nghttp2_hd_inflate_del(inf);
}

/* ---- he ---- */

static int be32(const buf_t *b, size_t *off, uint32_t *v) {
  if (b->n - *off < 4) return -1;
  const uint8_t *p = b->p + *off;
  *v = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
  *off += 4;
  return 0;
}

static void run_he(const buf_t *in, size_t table, buf_t *res) {
  size_t off = 0, n = 0, cap = 0;
  nghttp2_nv *nva = NULL;
  const char *bad = NULL;
  while (off < in->n) {
    uint32_t nl, vl;
    if (be32(in, &off, &nl) || in->n - off < nl) { bad = "malformed blob"; break; }
    const uint8_t *name = in->p + off;
    off += nl;
    if (be32(in, &off, &vl) || in->n - off < vl) { bad = "malformed blob"; break; }
    const uint8_t *val = in->p + off;
    off += vl;
    if (n == cap) {
      cap = cap ? cap * 2 : 8;
      nva = xrealloc(nva, cap * sizeof *nva);
    }
    nva[n].name = (uint8_t *)name;
    nva[n].namelen = nl;
    nva[n].value = (uint8_t *)val;
    nva[n].valuelen = vl;
    nva[n].flags = NGHTTP2_NV_FLAG_NONE;
    n++;
  }
  if (bad) {
    buf_printf(res, "{\"hex\":\"\",\"err\":\"%s\"}", bad);
    free(nva);
    return;
  }
  nghttp2_hd_deflater *def;
  if (nghttp2_hd_deflate_new(&def, table)) {
    buf_str(res, "{\"hex\":\"\",\"err\":\"deflate_new failed\"}");
    free(nva);
    return;
  }
  size_t bound = nghttp2_hd_deflate_bound(def, nva, n);
  uint8_t *o = xrealloc(NULL, bound);
  nghttp2_ssize r = nghttp2_hd_deflate_hd2(def, o, bound, nva, n);
  if (r < 0) {
    buf_printf(res, "{\"hex\":\"\",\"err\":\"deflate_hd2: %s\"}", nghttp2_strerror((int)r));
  } else {
    buf_str(res, "{\"hex\":\"");
    buf_hex(res, o, (size_t)r);
    buf_str(res, "\"}");
  }
  free(o);
  free(nva);
  nghttp2_hd_deflate_del(def);
}

/* ---- main ---- */

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--version")) {
    printf("nghttp2 %s\n", nghttp2_version(0)->version_str);
    return 0;
  }
  char *line = NULL;
  size_t cap = 0;
  ssize_t len;
  while ((len = getline(&line, &cap, stdin)) >= 0) {
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
    if (!len) continue;
    char *f[5];
    int nf = 0;
    char *s = line;
    f[nf++] = s;
    for (; *s && nf < 5; s++)
      if (*s == '\t') {
        *s = 0;
        f[nf++] = s + 1;
      }
    buf_t res = {0};
    if (nf < 5) {
      printf("%s\t-\t{\"err\":\"malformed case line\"}\n", f[0]);
      continue;
    }
    const char *kind = f[1];
    buf_t in = {0};
    if (unhex(f[4], strlen(f[4]), &in)) {
      buf_str(&res, "{\"err\":\"bad hex\"}");
    } else if (!strcmp(kind, "h2")) {
      run_h2(&in, !strcmp(f[2], "byte"), &res);
    } else if (!strcmp(kind, "hd")) {
      run_hd(&in, (size_t)strtoull(f[3], NULL, 10), &res);
    } else if (!strcmp(kind, "he")) {
      run_he(&in, (size_t)strtoull(f[3], NULL, 10), &res);
    } else {
      buf_str(&res, "{\"err\":\"unknown kind\"}");
    }
    fputs(f[0], stdout);
    fputc('\t', stdout);
    fputs(f[2], stdout);
    fputc('\t', stdout);
    fwrite(res.p, 1, res.n, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    buf_free(&in);
    buf_free(&res);
  }
  free(line);
  return 0;
}

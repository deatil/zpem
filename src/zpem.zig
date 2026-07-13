/// pem.zig implements the PEM data encoding, which originated in Privacy Enhanced Mail.
/// The most common use of PEM encoding today is in TLS keys and certificates.
/// See RFC 1421.
const std = @import("std");
const mem = std.mem;
const sort = std.sort;
const testing = std.testing;
const base64 = std.crypto.codecs.base64;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const ArraySlice = Writer.Allocating;
const StringKeyHashMap = std.hash_map.StringHashMap([]const u8);

/// A Block represents a PEM encoded structure.
///
/// The encoded form is:
///
///  -----BEGIN Type-----
///  Headers
///  base64-encoded Bytes
///  -----END Type-----
///
/// where Headers is a possibly empty sequence of Key: Value lines.
pub const Block = struct {
    /// The type, taken from the preamble (i.e. "RSA PRIVATE KEY").
    type: []const u8,
    /// Optional headers.
    headers: StringKeyHashMap,
    /// The decoded bytes of the contents. Typically a DER encoded ASN.1 structure.
    bytes: []const u8,
    alloc: Allocator,

    const Self = @This();

    pub fn init(alloc: Allocator) Block {
        const headers = StringKeyHashMap.init(alloc);

        return .{
            .type = "",
            .headers = headers,
            .bytes = "",
            .alloc = alloc,
        };
    }

    /// Frees any memory that was allocated during Pem decoding.
    pub fn deinit(self: *Self) void {
        var headers = self.headers;
        headers.deinit();

        self.alloc.free(self.bytes);

        self.* = undefined;
    }

    /// set der bytes
    pub fn withBytes(self: *Self, b: []const u8) !void {
        self.bytes = try self.alloc.dupe(u8, b[0..]);
    }

    /// get der bytes
    pub fn getBytes(self: *const Self) ![]const u8 {
        return self.alloc.dupe(u8, self.bytes[0..]);
    }
};

pub const Error = error{
    NotPemData,
    PemDataEmpty,
    PemHeaderKeyEmpty,
    PemHeaderKeyHasColon,
    PemHeaderValueHasColon,
};

const pem_start = "\n-----BEGIN ";
const pem_end = "\n-----END ";
const pem_end_of_line = "-----";
const colon = ":";

/// decode will find the next PEM formatted block (certificate, private key
/// etc) in the input. It returns that block and the remainder of the input.
pub fn decode(allocator: Allocator, data: []const u8) !Block {
    var rest = data;

    while (true) {
        if (mem.startsWith(u8, rest, pem_start[1..])) {
            rest = rest[pem_start.len - 1 ..];
        } else {
            const cut_data = cut(rest, pem_start);
            if (cut_data.found) {
                rest = cut_data.after;
            } else {
                return Error.NotPemData;
            }
        }

        const line_data = getLine(rest);
        if (!mem.endsWith(u8, line_data.line, pem_end_of_line)) {
            continue;
        }

        const type_line = line_data.line[0 .. line_data.line.len - pem_end_of_line.len];

        rest = line_data.rest;

        var p = Block.init(allocator);
        p.type = type_line;

        while (true) {
            if (rest.len == 0) {
                return Error.PemDataEmpty;
            }

            const line_data2 = getLine(rest);

            const cut_data = cut(line_data2.line, colon);
            if (!cut_data.found) {
                break;
            }

            const key = trimSpace(cut_data.before);
            const val = trimSpace(cut_data.after);

            try p.headers.put(key, val);

            rest = line_data2.rest;
        }

        var end_index: usize = 0;
        var end_trailer_index: usize = 0;

        if (p.headers.count() == 0 and mem.startsWith(u8, rest, pem_end[1..])) {
            end_index = 0;
            end_trailer_index = pem_end.len - 1;
        } else {
            if (mem.indexOf(u8, rest, pem_end)) |val| {
                end_index = val;
                end_trailer_index = end_index + pem_end.len;
            } else {
                continue;
            }
        }

        var end_trailer = rest[end_trailer_index..];
        const end_trailer_len = type_line.len + pem_end_of_line.len;
        if (end_trailer.len < end_trailer_len) {
            continue;
        }

        const rest_of_end_line = end_trailer[end_trailer_len..];
        end_trailer = end_trailer[0..end_trailer_len];
        if (!mem.startsWith(u8, end_trailer, type_line) or !mem.endsWith(u8, end_trailer, pem_end_of_line)) {
            continue;
        }

        const line_data2 = getLine(rest_of_end_line);
        if (line_data2.line.len != 0) {
            continue;
        }

        const base64_data = try removeAllSpacesAndTabs(allocator, rest[0..end_index]);
        defer allocator.free(base64_data);

        const base64_decoded = try base64Decode(allocator, base64_data);
        defer allocator.free(base64_decoded);

        try p.withBytes(base64_decoded);

        return p;
    }
}

const nl = "\n";

const pem_line_length = 64;

fn appendHeader(list: *Writer, k: []const u8, v: []const u8) !void {
    try list.writeAll(k);
    try list.writeAll(":");
    try list.writeAll(v);
    try list.writeAll("\n");
}

/// Encodes pem bytes.
pub fn encode(allocator: Allocator, b: Block) ![:0]u8 {
    var hc = try b.headers.clone();
    defer hc.deinit();

    var headers_it = hc.iterator();
    while (headers_it.next()) |kv| {
        if (kv.key_ptr.*.len == 0) {
            return Error.PemHeaderKeyEmpty;
        }
        if (mem.indexOf(u8, kv.key_ptr.*, ":") != null) {
            return Error.PemHeaderKeyHasColon;
        }

        if (mem.indexOf(u8, kv.value_ptr.*, ":") != null) {
            return Error.PemHeaderValueHasColon;
        }
    }

    var buf = ArraySlice.init(allocator);
    defer buf.deinit();

    const buf_writer = &buf.writer;
    try buf_writer.writeAll(pem_start[1..]);

    try buf_writer.writeAll(b.type);
    try buf_writer.writeAll("-----\n");

    if (b.headers.count() > 0) {
        const proc_type = "Proc-Type";

        var h = try allocator.alloc([]const u8, b.headers.count());
        defer allocator.free(h);

        var has_proc_type: bool = false;

        var kv_i: usize = 0;

        var hc2 = try b.headers.clone();
        defer hc2.deinit();

        var headers = hc2.iterator();
        while (headers.next()) |kv| {
            if (mem.eql(u8, kv.key_ptr.*, proc_type)) {
                has_proc_type = true;
                continue;
            }

            h[kv_i] = kv.key_ptr.*;
            kv_i += 1;
        }

        if (has_proc_type) {
            if (b.headers.get(proc_type)) |vv| {
                try appendHeader(buf_writer, proc_type, vv[0..]);
            }

            // strings sort a to z
            sort.block([]const u8, h[0 .. h.len - 1], {}, stringSort([]const u8));

            for (h[0 .. h.len - 1]) |k| {
                if (b.headers.get(k)) |val| {
                    try appendHeader(buf_writer, k, val);
                }
            }
        } else {
            // strings sort a to z
            sort.block([]const u8, h, {}, stringSort([]const u8));

            for (h) |k| {
                if (b.headers.get(k)) |val| {
                    try appendHeader(buf_writer, k, val);
                }
            }
        }

        try buf_writer.writeAll("\n");
    }

    const base64_encoded = try base64Encode(allocator, b.bytes);
    defer allocator.free(base64_encoded);

    var idx: usize = 0;
    while (true) {
        if (base64_encoded[idx..].len < pem_line_length) {
            try buf_writer.writeAll(base64_encoded[idx..]);
            try buf_writer.writeAll(nl);
            break;
        } else {
            try buf_writer.writeAll(base64_encoded[idx..(idx + pem_line_length)]);
            try buf_writer.writeAll(nl);

            idx += pem_line_length;
        }
    }

    try buf_writer.writeAll(pem_end[1..]);
    try buf_writer.writeAll(b.type);
    try buf_writer.writeAll("-----\n");

    return buf.toOwnedSliceSentinel(0);
}

pub fn stringSort(comptime T: type) fn (void, T, T) bool {
    return struct {
        pub fn inner(_: void, a: T, b: T) bool {
            // return false if a > b
            if (mem.order(u8, a, b) == .gt) {
                return false;
            }

            return true;
        }
    }.inner;
}

const LineData = struct {
    line: []const u8,
    rest: []const u8,
};

fn getLine(data: []const u8) LineData {
    var i = data.len;
    var j = i;

    if (mem.indexOf(u8, data, "\n")) |val| {
        i = val;
        j = i + 1;
        if (i > 0 and data[i - 1] == '\r') {
            i -= 1;
        }
    }

    return .{
        .line = mem.trimEnd(u8, data[0..i], " \t"),
        .rest = data[j..],
    };
}

/// removeAllSpacesAndTabs returns a copy of its input with all spaces and tabs
/// removed, if there were any. Otherwise, the input is returned unchanged.
fn removeAllSpacesAndTabs(alloc: Allocator, data: []const u8) ![:0]u8 {
    var buf = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer buf.deinit(alloc);

    for (data) |b| {
        if (b == ' ' or b == '\t' or b == '\n' or b == '\r') {
            continue;
        }

        try buf.append(alloc, b);
    }

    return buf.toOwnedSliceSentinel(alloc, 0);
}

const CutData = struct {
    before: []const u8,
    after: []const u8,
    found: bool,
};

fn cut(s: []const u8, sep: []const u8) CutData {
    if (mem.indexOf(u8, s, sep)) |i| {
        return .{
            .before = s[0..i],
            .after = s[i + sep.len ..],
            .found = true,
        };
    }

    return .{
        .before = s,
        .after = "",
        .found = false,
    };
}

/// TrimSpace returns a subslice of s by slicing off all leading and
/// trailing white space, as defined by Unicode.
fn trimSpace(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len) : (start += 1) {
        if (!std.ascii.isWhitespace(s[start])) {
            break;
        }
    }

    var stop = s.len - 1;
    while (stop > start) : (stop -= 1) {
        if (!std.ascii.isWhitespace(s[stop])) {
            break;
        }
    }

    if (start == stop) {
        return "";
    }

    return s[start..(stop + 1)];
}

fn base64Encode(alloc: Allocator, input: []const u8) ![]const u8 {
    const encode_len = base64.encodedLen(input.len, .standard);
    const buffer = try alloc.alloc(u8, encode_len);

    defer alloc.free(buffer);

    const res = try base64.encode(buffer, input, .standard);
    return alloc.dupe(u8, res[0..]);
}

fn base64Decode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decode_len = try base64.decodedLen(input.len, .standard);
    const buffer = try alloc.alloc(u8, decode_len);

    defer alloc.free(buffer);

    const res = try base64.decode(buffer, input, .standard);
    return alloc.dupe(u8, res[0..]);
}

test "ASN.1 type CERTIFICATE" {
    const byte =
        "-----BEGIN CERTIFICATE-----\n" ++
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz\n" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs\n" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh\n" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID\n" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB\n" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE\n" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow\n" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0\n" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=\n" ++
        "-----END CERTIFICATE-----\n";

    const alloc = testing.allocator;

    var pem = try decode(alloc, byte);
    defer pem.deinit();

    try testing.expectFmt("CERTIFICATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);

    const check =
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=";

    const bytes_encoded = try base64Encode(alloc, pem.bytes);
    defer alloc.free(bytes_encoded);

    try testing.expectEqualStrings(check, bytes_encoded);
}

test "ASN.1 type CERTIFICATE + Explanatory Text" {
    const byte =
        "Subject: CN=Atlantis\n" ++
        "Issuer: CN=Atlantis\n" ++
        "Validity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC\n" ++
        "-----BEGIN CERTIFICATE-----\n" ++
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz\n" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs\n" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh\n" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID\n" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB\n" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE\n" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow\n" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0\n" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=\n" ++
        "-----END CERTIFICATE-----\n";

    const alloc = testing.allocator;

    var pem = try decode(alloc, byte);
    defer pem.deinit();

    try testing.expectFmt("CERTIFICATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);

    const check =
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=";

    const bytes_encoded = try base64Encode(alloc, pem.bytes);
    defer alloc.free(bytes_encoded);

    try testing.expectEqualStrings(check, bytes_encoded);
}

test "ASN.1 type RSA PRIVATE With headers" {
    const byte =
        "-----BEGIN RSA PRIVATE-----\n" ++
        "ID: RSA IDs\n" ++
        "ABC: thsasd   \n" ++
        "\n" ++
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz\n" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs\n" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh\n" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID\n" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB\n" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE\n" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow\n" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0\n" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=\n" ++
        "-----END RSA PRIVATE-----\n";

    const alloc = testing.allocator;

    var pem = try decode(alloc, byte);
    defer pem.deinit();

    try testing.expectFmt("RSA PRIVATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);

    const header_1 = pem.headers.get("ID").?;
    const header_2 = pem.headers.get("ABC").?;
    try testing.expectFmt("RSA IDs", "{s}", .{header_1});
    try testing.expectFmt("thsasd", "{s}", .{header_2});

    const check =
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=";

    const bytes_encoded = try base64Encode(alloc, pem.bytes);
    defer alloc.free(bytes_encoded);

    try testing.expectEqualStrings(check, bytes_encoded);
}

test "encode pem bin" {
    const alloc = testing.allocator;

    var pp = Block.init(alloc);
    pp.type = "RSA PRIVATE";
    try pp.headers.put("TTTYYY", "dghW66666");
    try pp.headers.put("Proc-Type", "4,Encond");
    try pp.withBytes("pem bytes");

    defer pp.deinit();

    const encoded_pem = try encode(alloc, pp);
    defer alloc.free(encoded_pem);

    const check =
        \\-----BEGIN RSA PRIVATE-----
        \\Proc-Type:4,Encond
        \\TTTYYY:dghW66666
        \\
        \\cGVtIGJ5dGVz
        \\-----END RSA PRIVATE-----
        \\
    ;

    try testing.expectFmt(check, "{s}", .{encoded_pem});

    var pem = try decode(alloc, encoded_pem);
    defer pem.deinit();

    try testing.expectFmt("RSA PRIVATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);
    try testing.expectFmt("pem bytes", "{s}", .{pem.bytes});

    const header_1 = pem.headers.get("Proc-Type").?;
    const header_2 = pem.headers.get("TTTYYY").?;
    try testing.expectFmt("4,Encond", "{s}", .{header_1});
    try testing.expectFmt("dghW66666", "{s}", .{header_2});
}

const std = @import("std");

const fmt = std.fmt;
const mem = std.mem;
const sort = std.sort;
const testing = std.testing;
const base64 = std.base64;
const StringHashMap = std.hash_map.StringHashMap;
const Allocator = mem.Allocator;

const bytes = @import("bytes.zig");

/// pem block data.
pub const Block = struct {
    const Self = @This();
    
    /// The pem type.
    type: []const u8,
    /// Optional headers.
    headers: StringHashMap([]const u8),
    /// Decoded content of a PEM file.
    bytes: []const u8,

    allocator: Allocator,

    /// init
    pub fn init(allocator: Allocator) Block {
        const headers = StringHashMap([]const u8).init(allocator);
        
        return .{
            .type = "",
            .headers = headers,
            .bytes = "",
            .allocator = allocator,
        };
    }

    /// initWithType
    pub fn initWithType(allocator: Allocator, type_line: []const u8) Block {
        const headers = StringHashMap([]const u8).init(allocator);
        
        return .{
            .type = type_line,
            .headers = headers,
            .bytes = "",
            .allocator = allocator,
        };
    }

    /// Frees any memory that was allocated during Pem decoding.
    pub fn deinit(self: *Self) void {
        var headers = self.headers;
        headers.deinit();
        
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

// pem errors
pub const Error = error {
    NotPemData,
    PemDataEmpty,
    PemHeaderHasColon,
};

const pem_start = "\n-----BEGIN ";
const pem_end = "\n-----END ";
const pem_end_of_line = "-----";
const colon = ":";

/// Decodes pem bytes.
pub fn decode(allocator: Allocator, data: []const u8) (Error || Allocator.Error || std.base64.Error)!Block {
    var rest = data;
    
    while (true) {
        if (bytes.hasPrefix(rest, pem_start[1..])) {
            rest = rest[pem_start.len-1..];
        } else {
            const cut_data = bytes.cut(rest, pem_start);
            if (cut_data.found) {
                rest = cut_data.after;
            } else {
                return Error.NotPemData;
            }
        }
        
        const line_data = bytes.getLine(rest);
        if (!bytes.hasSuffix(line_data.line, pem_end_of_line)) {
            continue;
        }
        
        const type_line = line_data.line[0 .. line_data.line.len-pem_end_of_line.len];

        rest = line_data.rest;
        
        var p = Block.initWithType(allocator, type_line);
        
        while (true) {
            if (rest.len == 0) {
                return Error.PemDataEmpty;
            }
            
            const line_data2 = bytes.getLine(rest);
            
            const cut_data = bytes.cut(line_data2.line, colon);
            if (!cut_data.found) {
                break;
            }
            
            const key = bytes.trimSpace(cut_data.before);
            const val = bytes.trimSpace(cut_data.after);
           
            try p.headers.put(key, val);
            
            rest = line_data2.rest;
        }
        
        var end_index: usize = 0; 
        var end_trailer_index: usize = 0;
        
        if (p.headers.count() == 0 and bytes.hasPrefix(rest, pem_end[1..])) {
            end_index = 0;
            end_trailer_index = pem_end.len - 1;
        } else {
            end_index = mem.indexOf(u8, rest, pem_end).?;
            end_trailer_index = end_index + pem_end.len;
        }
        
        if (end_index < 0) {
            continue;
        }
        
        const end_trailer = rest[end_trailer_index..];
        const end_trailer_len = type_line.len + pem_end_of_line.len;
        if (end_trailer.len < end_trailer_len) {
            continue;
        }

        const rest_of_end_line = end_trailer[end_trailer_len..];
        const end_trailer2 = end_trailer[0..end_trailer_len];
        if (!bytes.hasPrefix(end_trailer2, type_line) or !bytes.hasSuffix(end_trailer2, pem_end_of_line)) {
            continue;
        }
        
        const line_data2 = bytes.getLine(rest_of_end_line);
        if (line_data2.line.len != 0) {
            continue;
        }
        
        const base64_data = try bytes.removeSpacesAndTabs(allocator, rest[0..end_index]);
        const len = try std.base64.standard.Decoder.calcSizeForSlice(base64_data);

        const decoded_data = try allocator.alloc(u8, len);
        errdefer allocator.free(decoded_data);
        try std.base64.standard.Decoder.decode(decoded_data, base64_data);
        
        p.bytes = decoded_data;

        return p;
    }
}

const nl = "\n";

const pem_line_length = 64;

fn writeHeader(allocator: Allocator, k: []const u8, v: []const u8) ![:0]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try buf.appendSlice(k);
    try buf.appendSlice(":");
    try buf.appendSlice(v);
    try buf.appendSlice("\n");

    return buf.toOwnedSliceSentinel(0);
}

/// Encodes pem bytes.
pub fn encode(allocator: Allocator, b: Block) ![:0]u8 {
    var headers1 = (try b.headers.clone()).iterator();
    while (headers1.next()) |kv| {
        if (bytes.contains(kv.value_ptr.*, ":")) {
            return Error.PemHeaderHasColon;
        }
    }
    
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try buf.appendSlice(pem_start[1..]);

    try buf.appendSlice(b.type);
    try buf.appendSlice("-----\n");

    var alloc = std.heap.ArenaAllocator.init(allocator);
    defer alloc.deinit();
    
    if (b.headers.count() > 0) {
        const proc_type = "Proc-Type";

        var h = try alloc.allocator().alloc([]const u8, b.headers.count());

        var has_proc_type: bool = false;
        
        var kv_i: usize = 0;

        var headers2 = (try b.headers.clone()).iterator();
        while (headers2.next()) |kv| {
            if (mem.eql(u8, kv.key_ptr.*, proc_type)) {
                has_proc_type = true;
                continue;
            }

            h[kv_i] = kv.key_ptr.*;
            kv_i += 1;
        }

        if (has_proc_type) {
            if (b.headers.get(proc_type) != null) {
                const vv = b.headers.get(proc_type).?;
                const proc_data = try writeHeader(allocator, proc_type, vv[0..]);

                try buf.appendSlice(proc_data);
            }

            h.len -= 1;
            h = h[0..];
        }

        // strings sort a to z
        sort.block([]const u8, h, {}, stringSort([]const u8));
        
        for (h) |k| {
            if (b.headers.get(k) != null) {
                const header_data = try writeHeader(allocator, k, b.headers.get(k).?);

                try buf.appendSlice(header_data);
            }
        }

        try buf.appendSlice("\n");
    }

    const bytes_len = base64.standard.Encoder.calcSize(b.bytes.len);
    const buffer = try alloc.allocator().alloc(u8, bytes_len);

    const banse64_encoded = base64.standard.Encoder.encode(buffer, b.bytes);

    var idx: usize = 0;
    while (true) {
        if (banse64_encoded[idx..].len < pem_line_length) {
            try buf.appendSlice(banse64_encoded[idx..]);
            try buf.appendSlice(nl);
            break;
        } else {
            try buf.appendSlice(banse64_encoded[idx..(idx+pem_line_length)]);
            try buf.appendSlice(nl);

            idx += pem_line_length;
        }
    }

    try buf.appendSlice(pem_end[1..]);
    try buf.appendSlice(b.type);
    try buf.appendSlice("-----\n");

    return buf.toOwnedSliceSentinel(0);
}

pub fn stringSort(comptime T: type) fn (void, T, T) bool {
    return struct {
        pub fn inner(_: void, a: T, b: T) bool {
            if (a.len < b.len) {
                for (a, 0..) |aa, i| {
                    if (aa > b[i]) {
                        return false;
                    }
                }
            } else {
                for (b, 0..) |bb, j| {
                    if (bb < a[j]) {
                        return false;
                    }
                }
            }

            return true;
        }
    }.inner;
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

    const alloc = std.heap.page_allocator;
    var pem = try decode(alloc, byte);
    defer pem.deinit();

    try testing.expectFmt("CERTIFICATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);
    try testing.expectFmt("{ 30, 82, 1, 99, 30, 82, 1, 47, a0, 3, 2, 1, 2, 2, 1, 2a, 30, 9, 6, 5, 2b, e, 3, 2, 1d, 5, 0, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 30, 1e, 17, d, 31, 32, 30, 37, 30, 39, 30, 33, 31, 30, 33, 38, 5a, 17, d, 31, 33, 30, 37, 30, 39, 30, 33, 31, 30, 33, 37, 5a, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 30, 5c, 30, d, 6, 9, 2a, 86, 48, 86, f7, d, 1, 1, 1, 5, 0, 3, 4b, 0, 30, 48, 2, 41, 0, bb, e0, 57, a3, e9, a2, 69, b0, c8, 1c, 7c, 7e, ca, ab, aa, ce, a3, 61, 47, 29, ff, 5e, d9, 9, 20, 81, d5, 71, 8b, 47, bc, 85, fe, 4b, 5c, 79, 12, b8, c, a0, 77, a1, c9, ca, 68, c5, b1, 2b, 66, 65, 51, e0, 60, aa, d5, 2d, 9d, 88, d9, 91, 15, 90, 91, b5, 2, 3, 1, 0, 1, a3, 81, 89, 30, 81, 86, 30, c, 6, 3, 55, 1d, 13, 1, 1, ff, 4, 2, 30, 0, 30, 20, 6, 3, 55, 1d, 4, 1, 1, ff, 4, 16, 30, 14, 30, e, 30, c, 6, a, 2b, 6, 1, 4, 1, 82, 37, 2, 1, 15, 3, 2, 7, 80, 30, 1d, 6, 3, 55, 1d, 25, 4, 16, 30, 14, 6, 8, 2b, 6, 1, 5, 5, 7, 3, 2, 6, 8, 2b, 6, 1, 5, 5, 7, 3, 3, 30, 35, 6, 3, 55, 1d, 1, 4, 2e, 30, 2c, 80, 10, 34, 8c, e9, d2, 4a, e2, 7, 62, 69, d5, af, 21, c0, 77, 2c, c, a1, 15, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 82, 1, 2a, 30, 9, 6, 5, 2b, e, 3, 2, 1d, 5, 0, 3, 41, 0, a8, ba, 1d, 10, 5a, 34, 42, f9, 47, 49, f9, ea, 7b, df, 72, 54, d, 69, 78, 83, 4f, 5e, f8, b9, ff, a5, a2, 3c, c0, e2, 58, 55, 22, 77, 34, 20, bc, 29, 9d, 9d, 62, cc, be, c, 94, 8f, 5e, 9, 21, e1, 55, 0, 47, 12, 9d, ae, 41, d5, c9, 7, e7, 79, 7, 28 }", "{x}", .{pem.bytes});
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

    const alloc = std.heap.page_allocator;
    var pem = try decode(alloc, byte);
    defer pem.deinit();

    try testing.expectFmt("CERTIFICATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);
    try testing.expectFmt("{ 30, 82, 1, 99, 30, 82, 1, 47, a0, 3, 2, 1, 2, 2, 1, 2a, 30, 9, 6, 5, 2b, e, 3, 2, 1d, 5, 0, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 30, 1e, 17, d, 31, 32, 30, 37, 30, 39, 30, 33, 31, 30, 33, 38, 5a, 17, d, 31, 33, 30, 37, 30, 39, 30, 33, 31, 30, 33, 37, 5a, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 30, 5c, 30, d, 6, 9, 2a, 86, 48, 86, f7, d, 1, 1, 1, 5, 0, 3, 4b, 0, 30, 48, 2, 41, 0, bb, e0, 57, a3, e9, a2, 69, b0, c8, 1c, 7c, 7e, ca, ab, aa, ce, a3, 61, 47, 29, ff, 5e, d9, 9, 20, 81, d5, 71, 8b, 47, bc, 85, fe, 4b, 5c, 79, 12, b8, c, a0, 77, a1, c9, ca, 68, c5, b1, 2b, 66, 65, 51, e0, 60, aa, d5, 2d, 9d, 88, d9, 91, 15, 90, 91, b5, 2, 3, 1, 0, 1, a3, 81, 89, 30, 81, 86, 30, c, 6, 3, 55, 1d, 13, 1, 1, ff, 4, 2, 30, 0, 30, 20, 6, 3, 55, 1d, 4, 1, 1, ff, 4, 16, 30, 14, 30, e, 30, c, 6, a, 2b, 6, 1, 4, 1, 82, 37, 2, 1, 15, 3, 2, 7, 80, 30, 1d, 6, 3, 55, 1d, 25, 4, 16, 30, 14, 6, 8, 2b, 6, 1, 5, 5, 7, 3, 2, 6, 8, 2b, 6, 1, 5, 5, 7, 3, 3, 30, 35, 6, 3, 55, 1d, 1, 4, 2e, 30, 2c, 80, 10, 34, 8c, e9, d2, 4a, e2, 7, 62, 69, d5, af, 21, c0, 77, 2c, c, a1, 15, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 82, 1, 2a, 30, 9, 6, 5, 2b, e, 3, 2, 1d, 5, 0, 3, 41, 0, a8, ba, 1d, 10, 5a, 34, 42, f9, 47, 49, f9, ea, 7b, df, 72, 54, d, 69, 78, 83, 4f, 5e, f8, b9, ff, a5, a2, 3c, c0, e2, 58, 55, 22, 77, 34, 20, bc, 29, 9d, 9d, 62, cc, be, c, 94, 8f, 5e, 9, 21, e1, 55, 0, 47, 12, 9d, ae, 41, d5, c9, 7, e7, 79, 7, 28 }", "{x}", .{pem.bytes});
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

    const alloc = std.heap.page_allocator;
    var pem = try decode(alloc, byte);
    defer pem.deinit();

    try testing.expectFmt("RSA PRIVATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);

    const header_1 = pem.headers.get("ID").?;
    const header_2 = pem.headers.get("ABC").?;
    try testing.expectFmt("RSA IDs", "{s}", .{header_1});
    try testing.expectFmt("thsasd", "{s}", .{header_2});

    try testing.expectFmt("{ 30, 82, 1, 99, 30, 82, 1, 47, a0, 3, 2, 1, 2, 2, 1, 2a, 30, 9, 6, 5, 2b, e, 3, 2, 1d, 5, 0, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 30, 1e, 17, d, 31, 32, 30, 37, 30, 39, 30, 33, 31, 30, 33, 38, 5a, 17, d, 31, 33, 30, 37, 30, 39, 30, 33, 31, 30, 33, 37, 5a, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 30, 5c, 30, d, 6, 9, 2a, 86, 48, 86, f7, d, 1, 1, 1, 5, 0, 3, 4b, 0, 30, 48, 2, 41, 0, bb, e0, 57, a3, e9, a2, 69, b0, c8, 1c, 7c, 7e, ca, ab, aa, ce, a3, 61, 47, 29, ff, 5e, d9, 9, 20, 81, d5, 71, 8b, 47, bc, 85, fe, 4b, 5c, 79, 12, b8, c, a0, 77, a1, c9, ca, 68, c5, b1, 2b, 66, 65, 51, e0, 60, aa, d5, 2d, 9d, 88, d9, 91, 15, 90, 91, b5, 2, 3, 1, 0, 1, a3, 81, 89, 30, 81, 86, 30, c, 6, 3, 55, 1d, 13, 1, 1, ff, 4, 2, 30, 0, 30, 20, 6, 3, 55, 1d, 4, 1, 1, ff, 4, 16, 30, 14, 30, e, 30, c, 6, a, 2b, 6, 1, 4, 1, 82, 37, 2, 1, 15, 3, 2, 7, 80, 30, 1d, 6, 3, 55, 1d, 25, 4, 16, 30, 14, 6, 8, 2b, 6, 1, 5, 5, 7, 3, 2, 6, 8, 2b, 6, 1, 5, 5, 7, 3, 3, 30, 35, 6, 3, 55, 1d, 1, 4, 2e, 30, 2c, 80, 10, 34, 8c, e9, d2, 4a, e2, 7, 62, 69, d5, af, 21, c0, 77, 2c, c, a1, 15, 30, 13, 31, 11, 30, f, 6, 3, 55, 4, 3, 13, 8, 41, 74, 6c, 61, 6e, 74, 69, 73, 82, 1, 2a, 30, 9, 6, 5, 2b, e, 3, 2, 1d, 5, 0, 3, 41, 0, a8, ba, 1d, 10, 5a, 34, 42, f9, 47, 49, f9, ea, 7b, df, 72, 54, d, 69, 78, 83, 4f, 5e, f8, b9, ff, a5, a2, 3c, c0, e2, 58, 55, 22, 77, 34, 20, bc, 29, 9d, 9d, 62, cc, be, c, 94, 8f, 5e, 9, 21, e1, 55, 0, 47, 12, 9d, ae, 41, d5, c9, 7, e7, 79, 7, 28 }", "{x}", .{pem.bytes});

}

test "encode pem bin" {
    const alloc = std.heap.page_allocator;
    
    var pp = Block.init(alloc);
    pp.type = "RSA PRIVATE";
    try pp.headers.put("TTTYYY", "dghW66666");
    try pp.headers.put("Proc-Type", "4,Encond");
    pp.bytes = "pem bytes";

    const allocator = std.heap.page_allocator;
    const encoded_pem = try encode(allocator, pp);

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

    // =====

    const alloc2 = std.heap.page_allocator;
    var pem = try decode(alloc2, encoded_pem);
    defer pem.deinit();

    try testing.expectFmt("RSA PRIVATE", "{s}", .{pem.type});
    try testing.expect(pem.bytes.len > 0);
    try testing.expectFmt("pem bytes", "{s}", .{pem.bytes});

    const header_1 = pem.headers.get("Proc-Type").?;
    const header_2 = pem.headers.get("TTTYYY").?;
    try testing.expectFmt("4,Encond", "{s}", .{header_1});
    try testing.expectFmt("dghW66666", "{s}", .{header_2});
    
}


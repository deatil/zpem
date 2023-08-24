const std = @import("std");

const fmt = std.fmt;
const mem = std.mem;
const sort = std.sort;
const base64 = std.base64;
const Allocator = mem.Allocator;

const bytes = @import("bytes.zig");

/// Convenience type that contains the `AsnType`
/// and the base64 decoded content of the file.
pub const Block = struct {
    /// The type
    type: []const u8,
    /// Optional headers.
    headers: std.hash_map.StringHashMap([]const u8),
    /// Decoded content of a PEM file
    bytes: []const u8,

    /// init
    pub fn init(allocator: Allocator) Block {
        var headers = std.hash_map.StringHashMap([]const u8).init(allocator);
        
        return .{
            .type = "",
            .headers = headers,
            .bytes = "",
        };
    }

    /// initWithType
    pub fn initWithType(allocator: Allocator, type_line: []const u8) Block {
        var headers = std.hash_map.StringHashMap([]const u8).init(allocator);
        
        return .{
            .type = type_line,
            .headers = headers,
            .bytes = "",
        };
    }

    /// Frees any memory that was allocated during Pem decoding.
    /// Must provide the same `Allocator` that was given to the decoder.
    pub fn deinit(self: *Block, allocator: Allocator) void {
        self.headers.deinit();
        
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

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
        
        var headers = std.hash_map.StringHashMap([]const u8).init(allocator);
        
        var p = Block{
            .type = type_line,
            .headers = headers,
            .bytes = "",
        };
        
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

pub fn string_asc(comptime T: type) fn (void, T, T) bool {
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

        // todo: fiexed strings sort.
        sort.block([]const u8, h, {}, string_asc([]const u8));
        
        for (h) |k| {
            if (b.headers.get(k) != null) {
                const header_data = try writeHeader(allocator, k, b.headers.get(k).?);

                try buf.appendSlice(header_data);
            }
        }

        try buf.appendSlice("\n");
    }

    var bytes_len = base64.standard.Encoder.calcSize(b.bytes.len);
    var buffer = try alloc.allocator().alloc(u8, bytes_len);

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

    var pem = try decode(std.testing.allocator, byte);
    defer pem.deinit(std.testing.allocator);

    try std.testing.expectEqual("CERTIFICATE", pem.type);
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

    var pem = try decode(std.testing.allocator, byte);
    defer pem.deinit(std.testing.allocator);

    try std.testing.expectEqual("CERTIFICATE", pem.type);
}

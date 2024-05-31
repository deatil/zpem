## zpem 

A pem parse and encode library for Zig.


### Env

 - Zig >= 0.12


### Get Starting

* parse pem

~~~zig
const std = @import("std");
const pem = @import("zpem");

pub fn main() !void {
    const bytes =
        "-----BEGIN RSA PRIVATE-----\n" ++
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

    const allocator = std.heap.page_allocator;
    var p = try pem.decode(allocator, bytes);
    defer p.deinit(allocator);

    std.debug.print("pem type: {s}\n", .{p.type});
    std.debug.print("pem bytes: {x}\n", .{p.bytes});

    // get header data
    const header = p.headers.get("ABC").?;
    std.debug.print("pem header: {s}\n", .{header});
}
~~~

* encode pem

~~~zig
const std = @import("std");
const pem = @import("zpem");

pub fn main() !void {
    const alloc = std.heap.page_allocator;
    
    // var pp = pem.Block.initWithType(alloc, "RSA PRIVATE");
    var pp = pem.Block.init(allocator);
    pp.type = "RSA PRIVATE";
    try pp.headers.put("TTTYYY", "dghW66666");
    try pp.headers.put("Proc-Type", "4,Encond");
    pp.bytes = "pem bytes";

    const allocator = std.heap.page_allocator;
    var encoded_pem = try pem.encode(allocator, pp);

    std.debug.print("pem encoded: {s}\n", .{encoded_pem});
}
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).

## zpem 

zpem 是一个使用 zig 语言解析生成 pem 格式证书的通用库


### 环境要求

 - Zig >= 0.11


### 下载安装

~~~cmd
git clone github.com/deatil/zpem
~~~

### 开始使用

解析 pem 格式证书
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

    std.debug.print("pem type data: {s}\n", .{p.type});

    var header = p.headers.get("ABC").?;
    std.debug.print("pem header data: {s}\n", .{header});
}
~~~

生成 pem 格式证书
~~~zig
const std = @import("std");
const pem = @import("zpem");

pub fn main() !void {
    // var pp = pem.Block.initWithType(allocator, "RSA PRIVATE");
    var pp = pem.Block.init(allocator);
    pp.type = "RSA PRIVATE";
    try pp.headers.put("TTTYYY", "dghW66666");
    try pp.headers.put("Proc-Type", "4,Encond");
    pp.bytes = []const u8;

    const allocator = std.heap.page_allocator;
    var encoded3 = try pem.encode(allocator, pp);

    std.debug.print("pem encode data: {s}\n", .{encoded3});
}


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。

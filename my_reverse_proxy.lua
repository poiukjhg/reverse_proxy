--author zyp
socket = require 'socket'
copas = require 'copas'
md5_f = require("md5")
rbt = require("rbt")

local local_host = "*"
local local_port = 8080
local local_ip = nil
--local up_host = "pcdowncc.titan.imgo.tv" 
--local up_host_cname = "pcdowncc.titan.ccgslb.net"
--local up_host = "mvvideo2.meitudata.com" 
--local up_host_cname = "meitudata.ccgslb.net"
--local up_host = "nettv.wasu.cn" 
--local up_host_cname = "nettv.wasu.ccgslb.net"
local up_port = 80
local cache_len = 32*1024
local cc_down_file = "/etc/app_conf/ccapp/conf/ccapp_domain_cfg.conf"
local log_max_num = 0
local log_ver_cfg_file = "/etc/app_conf/ccapp/nginx/logformat.ccapp_nginx.conf"
local l_local_mac = io.popen("ifconfig eth0|grep HWaddr |awk '{print $5}'|tr -d \":\""):read()
local app_version = "0.0.0"
local log_version = "31"
local remote_log_sip = "smartgeek.chinacache.com"
local remote_log_sport = 7878
--print("Proxying from ".. local_host .. ":" .. local_port.." to ".. up_host .. ":" .. up_port)
local host_cname = {
    --[ up_host ] = up_host_cname
}
local servlog = {}
local cache_rbt = rbt:new()
local cache_timeout = 1000
local cache_path = "/tmp/ccapp_cache/"
local cache_total_len = 10*1024*1024
local cache_free_len = cache_total_len

local headers_parsers = {
    [ "connection" ]= function(h, test_socket)
        log("headers_parsers: " .. h)
        return nil, "Connection: close", nil
    end,
    [ "host" ]= function(h, test_socket)
        log("headers_parsers: " .. h)
        up_host = string.match(h, ":%s?([^%s:]+)")
        local remote_s = nil
        if test_socket == nil then
            local cname = host_cname[up_host]
            remote_s = socket.connect(cname, up_port)
            if remote_s == nil then
                remote_s = socket.connect(cname, up_port)
            end
            --remote_s:settimeout(0) 
            log("host = " .. (up_host or "").. ", cname= " ..(cname or ""))                       
        end
        --return remote_s , "Host: " .. up_host ..":"..up_port, up_host
        return remote_s , h, up_host
    end,
    --[[ "location" ]= function(h, test_socket)
        local  new, old ;
        if local_port == "80" then new = local_host else new = local_host .. ":" .. local_port end
        if up_port == "80" then old = up_host else old = up_host .. ":" .. up_port end
        return nil, string.gsub(h,old,new,1), nil;

    end,
     --]]  
    [ "user-agent" ]= function(h, test_socket)
        log("headers_parsers: " .. h)
        local agent = string.match(h, ":%s?(.+)")
        return nil, h, agent;
    end ,  
    [ "cookie" ] = function(h, test_socket)
        log("headers_parsers: " .. h)    
        local cookie = string.match(h, ":%s?(.+)")
        return nil, h, cookie; 
    end  
}

local server = assert(socket.bind(local_host, local_port))
function log(s)
    if arg[1] == "debug" then
        print(s)
    end    
end

function get_log_ver()
    str = assert(io.open(log_ver_cfg_file):read())
    log_version = string.match(str, "cc_speedup\" \"(%d+)")
    app_version = string.match(str, "cc_speedup\" \"%d+\" \"(%d+.%d+.%d+)\"")
    log("app_version = ".. app_version.. " log_version = "..log_version)
end
function add_d_quotation(str)
    return "\""..(str or "-").."\" "
end
--  log_format  cc_speedup  '"cc_speedup" "179" "2.2.5" "$time_local" "$msec" "$content_type" "$host" '
--                    '"$request" "$http_cookie" "$status" "$bytes_sent" "$request_time" "$upstream_response_time" '
--                    '"$upstream_addr" "$http_referer" "$http_user_agent" '
--                    '"$local_mac" "$client_mac" "" "$upstream_cache_status" ';
--"cc_speedup" "232" "2.2.5" "04/Feb/2016:13:23:35 +0800" "1454563415.644" "-" "appdl.hicloud.com" 
--"GET /dl/appdl/application/apk/e1/e1e38c48d8a1440b86b39cffefb4126b/com.iflytek.ringdiyclient.1504220943.apk?sign=mw@mw1429783927877 HTTP/1.1" 
--"-" "200" "5931954" "5.124" "3.824" "221.204.171.158:80" "-" "curl/7.35.0" "F0B4292B8D67" "64006a218a06" "" "-" 
function log_generate(l_host, l_req, l_cookie, l_status, l_byte_sent, l_request_time, l_upstream_response_time, l_upstream_addr, l_http_user_agent, l_local_mac, l_client_mac, l_ishit)
    local cur_time = os.time()
    local verify_code = md5_f.sumhexa(tostring(l_byte_sent or 0) .. "cc_speedup")
    local str = add_d_quotation("cc_speedup")..add_d_quotation(log_version) .. add_d_quotation(app_version) .. add_d_quotation(os.date("%d/%m/%Y %X", cur_time).." +0800")..add_d_quotation(cur_time)..add_d_quotation(l_cookie)..add_d_quotation(l_host)
    str = str .. add_d_quotation(l_req)..add_d_quotation("-")..add_d_quotation(l_status)..add_d_quotation(l_byte_sent)..add_d_quotation(l_request_time)..add_d_quotation(l_upstream_response_time)
    str = str .. add_d_quotation(l_upstream_addr)..add_d_quotation("-")..add_d_quotation(l_http_user_agent)..add_d_quotation(l_local_mac)..add_d_quotation(l_client_mac)..add_d_quotation("")..add_d_quotation(l_ishit)
    str = str.. "|" ..verify_code
    table.insert(servlog, str)
    log(str)
    logt_num = table.maxn(servlog)
    if logt_num >log_max_num then
        log("log send start")
        local remote_log_sock = socket.tcp()
        remote_log_sock:settimeout(1)
        remote_log_sock:connect(remote_log_sip, remote_log_sport)
        if remote_log_sock ~= nil then
            remote_log_sock:send(table.concat(servlog, "\n\r"))
            servlog = {}
            remote_log_sock:close()
            log("log send finish")
        else
            log("remote log server connect error")    
        end
        if logt_num >500 then
            log("log data in mem is too big, clear it")
            servlog = {}
        end
    end
end

function get_local_mac(ip_str)
    local  f = io.open("/proc/net/arp")
    if f then
        for per_line in f:lines() do
            per_ip = string.match(per_line, "(%d+.%d+.%d+.%d+)%s+")
            if per_ip == ip_str then
                local loc_mac = string.match(per_line, "%s+(%w+:%w+:%w+:%w+:%w+:%w+)%s+")
                loc_mac = string.gsub(loc_mac, ":", "")
                f:close()
                log("local_mac = " .. loc_mac)
                return loc_mac
            end 
        end         
    end     
    f:close()
    return ""
end

function handle_server_cname(cfg_file)
    local f = assert(io.open(cfg_file))
    for perline in f:lines() do
        local serv = string.match(perline, "([^%s#]+)#")
        local cname = string.match(perline, "#([^%s#]+)#")
        --log("serv = " .. serv .." cname = " .. cname)
        host_cname[serv] = cname
    end
    f:close()
    for i, v in pairs(host_cname) do       
        log("serv = " .. i .." cname = " .. v)
    end    
end

--if hit, update timestamp
function check_if_hit(uri_key)
    print("uri_key = "..uri_key)
    local w = cache_rbt.find_data(uri_key)
    if w ~= nil then
        cache_rbt:delete(v.key)
        cache_rbt:insert(tonumber(os.time()), uri_key)
        return "HIT"
    end
    return "-"
end

function get_method(l)
    return string.gsub(l,"^(%w+).*$","%1")
end

function parse_header(l, test_socket, log_table)
    local head, last
    for k in string.gmatch(l,"([^:%s]+)%s?:") do head = string.lower(k) ; break end
    if headers_parsers[head] ~= nil then
        up_s, l , temp_str=  headers_parsers[head](l, test_socket)
    end
    if head == "host" then
        log_table["l_host"] = temp_str
    end  
    if head == "user-agent" then
        log_table["l_http_user_agent"] = temp_str
    end      
    if head == "cookie" then
        log_table["l_cookie"] = temp_str
    end 
    if string.len(l) == 0 then last = true end
    return up_s, l .. "\r\n",last, l
end

function pass_headers(reader,writer,dir)
    local method, len 
    local header_t = {}
    local writer_s = writer
    local log_table = {true, true, true, true, true, true, true, true}
    local tmp_write = nil
    while true do
        local req = reader:receive()
        if req == nil then req = "" end
        if dir == "up" and method == nil then 
            method = get_method(req) 
            log_table["l_req"] = req
        end
        if string.lower(string.sub(req,0,14)) == "content-length" then len = string.gsub(req,"[^:]+:%s*(%d+)","%1") end
        if string.lower(string.sub(req,0,4)) =="http" then log_table["l_status"] = string.match(req, "%s+([^%s]+)%s+") end
        local tmp_write, header, last, h = parse_header(req, writer_s, log_table)
        if dir == "up" and writer_s == nil and tmp_write ~= nil then
            log("get writer")
            writer_s = tmp_write
            local tmpstr = tostring(writer_s:getpeername())..":"..tostring(up_port)
            log_table["l_upstream_addr"] = tmpstr
        end    
        table.insert(header_t, header)        
        log(dir .. " header " .. h)
        if last then break end
    end
    local str = table.concat(header_t, "")
    --log(str)
    log("send head")
    if writer_s == nil then
        print("writer_s is nil :" .. dir)
        return nil, nil, nil, nil
    end
    writer_s:send(str)   
    return writer_s, method, len, log_table
end

function pass_body(reader,writer, len, dir, cache_file_name)
    log("send body start")
    if len == nil then
        while true do
            local res, err, part = reader:receive(512)
            if err == "closed" or err == 'timeout' then
                log("receive error")
                if part ~= nil then 
                    --log(part)
                    --log("send 2")
                    writer:send(part) 
                end
                break
            end
            --log(res)
            --log("send 3")
            writer:send(res)
        end
    else        
        if len == 0 then return nil end
        local f = nil
        if dir == "down" and cache_file_name ~= nil then
            if tonumber(len) < cache_free_len then
                cache_rbt:insert(os.time(), cache_file_name)
                f = io.open(cache_path..cache_file_name, "a+")
                print("insert cache " .. cache_file_name)
                cache_free_len = cache_free_len - tonumber(len)
            end
        end
        if tonumber(len) < tonumber(cache_len) then
            local res, err, part =  reader:receive(len) 
            --log("send 4")       
            writer:send(res)
            if f then f:write(res) end
        else
            local seg_num = math.ceil(len / cache_len)
            local offset = 0
            while offset < seg_num do
                if offset ~= (seg_num-1) then
                    local res, err, part =  reader:receive(cache_len)
                    --log("send 5")
                    writer:send(res) 
                    if f then f:write(res) end                   
                else
                    local res, err, part =  reader:receive(len-offset*cache_len)
                    log("send last block")
                    writer:send(res)
                    if f then f:write(res) end
                end  
                offset = offset+1                  
            end --while                
        end
        if f then f:close() end
    end
end
function pass_down_from_cache(uri_key, down_sock)
    if down_sock == nil then
        return 
    end
    io.input(cache_path .. uri_key)  
    while true do
        local lines = io.read(cache_len)
        if not lines then break end
        down_sock:send(lines)
    end  
    io.input():close()
end

function handler(sk8)
    log("get in handler")
    local up_log_table = {}
    local down_log_table = {}
    local down_sock = copas.wrap(sk8)
    local l_request_time = os.time()
    local client_ip= sk8:getpeername()
    log("client ip = "..client_ip)
    l_client_mac= get_local_mac(client_ip)   
    log("pass up start")
    local up_sock, method,len, up_log_table = pass_headers(down_sock, nil, "up")
    if up_sock == nil then
        return
    end    
    if len ~= nil then 
        pass_body(down_sock, up_sock, tonumber(len),"up", nil) 
    end    
    log("pass up OK")
    log("pass down start")
    local l_upstream_response_time =os.time()
    local _, _, len2, down_log_table = pass_headers(up_sock, down_sock,"down")
    local uri = string.match(up_log_table["l_req"], "%s+([^%s]+)%s+")
    print("req = "..up_log_table["l_req"])
    print("uri = " .. uri )
    local uri_key = md5_f.sumhexa(up_log_table["l_host"]..uri .. tostring(len2))
    local if_hit = check_if_hit(uri_key)
    if if_hit == "HIT" then
        print("cache is hit")
        pass_down_from_cache(uri_key, down_sock)
    else    
        print("cache is not hit")
        pass_body(up_sock, down_sock,len2,"down", uri_key)
    end    
    l_upstream_response_time = os.difftime(os.time(), l_upstream_response_time)*0.8
    l_request_time = os.difftime(os.time(), l_request_time )
    log("pass down  OK")
    up_sock:close()
    _, l_byte_sent, _ = sk8:getstats()
    log_generate(up_log_table["l_host"], up_log_table["l_req"], up_log_table["l_cookie"], down_log_table["l_status"], l_byte_sent, l_request_time, l_upstream_response_time, up_log_table["l_upstream_addr"], up_log_table["l_http_user_agent"], l_local_mac, l_client_mac, if_hit)
end

function refresh_mem()
    local cur_nod = {}
    local c_timediff = 0
    while(true) do
        cur_nod = cache_rbt:min()
        if cur_nod.data == nil then
            break
        end    
        c_timediff = os.time() - cur_nod.key
        if c_timediff > cache_timeout then
            print("delete cache ".. cache_path..cur_nod.data)
            os.remove(cache_path..cur_nod.data)
            cache_rbt:delete(cur_nod.key)
        else
            break    
        end
    end
end

math.randomseed(os.time())
log_max_num = math.random(1, 10)
log("max num log = " .. log_max_num)
handle_server_cname(cc_down_file)
get_log_ver()
copas.addserver(server, handler)
copas.loop(100, refresh_mem)
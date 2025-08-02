@load policy/tuning/json-logs.zeek

module IoTDetection;
redef ignore_checksums = T;  # Bypass checksum validation
redef tcp_inactivity_timeout = 0sec;  # Track incomplete connections
export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time        &log;
        uid: string     &log;
        id_orig_h: addr &log;
        id_resp_h: addr &log;
        id_resp_p: port  &log;
        proto: int      &log;
        service: int    &log;
        duration: double &log;
        orig_bytes: double &log;
        resp_bytes: double &log;
        conn_state: int &log;
        missed_bytes: count &log;
        orig_pkts: count &log;
        orig_ip_bytes: count &log;
        resp_pkts: count &log;
        resp_ip_bytes: count &log;
        prediction: int &log &optional;
        confidence: double &log &optional;
    };

    global log_prediction: event(rec: Info);
}

# Encoding maps
global proto_encoding = {
    ["icmp"] = 0,
    ["tcp"] = 1,
    ["udp"] = 2,
    ["UNKNOWN"] = -1
};

global service_encoding = {
    ["-"] = 0,
    ["dhcp"] = 1,
    ["dns"] = 2,
    ["http"] = 3,
    ["ssh"] = 4,
    ["ssl"] = 5,
    ["irc"] = 6,
    ["UNKNOWN"] = -1
};

global conn_state_encoding = {
    ["S0"] = 0,
    ["S1"] = 1,
    ["S2"] = 2,
    ["S3"] = 3,
    ["SF"] = 4,
    ["REJ"] = 5,
    ["RSTO"] = 6,
    ["RSTR"] = 7,
    ["RSTOS0"] = 8,
    ["RSTRH"] = 9,
    ["SH"] = 10,
    ["SHR"] = 11,
    ["OTH"] = 12,
    ["UNKNOWN"] = -1
};

event zeek_init() {
    Log::create_stream(IoTDetection::LOG, [$columns=Info]);
}

function encode_proto(p: string): int {
    return p in proto_encoding ? proto_encoding[p] : proto_encoding["UNKNOWN"];
}

function encode_service(s: string): int {
    return s in service_encoding ? service_encoding[s] : service_encoding["UNKNOWN"];
}

function encode_conn_state(cs: string): int {
    return cs in conn_state_encoding ? conn_state_encoding[cs] : conn_state_encoding["UNKNOWN"];
}

event connection_state_remove(c: connection) {
    # Convert interval duration to double (seconds)
    local duration_val = (c$conn?$duration ? |c$conn$duration| : 0.0);
     # Handle potentially missing service field
    local service_str = (c$conn?$service ? c$conn$service : "-");
    local service_val = encode_service(service_str);
    
    
    # Extract features with proper field names
    local id_resp_p = c$id$resp_p;
    local proto_val = encode_proto(fmt("%s", c$conn$proto));
    
    local orig_bytes_val = c$orig$size + 0.0;  # Correct field: size
    local resp_bytes_val = c$resp$size + 0.0;   # Correct field: size
    local conn_state_val = encode_conn_state(fmt("%s", c$conn$conn_state));
    local missed_bytes_val = 0;
    local orig_pkts_val = c$orig$num_pkts;
    local orig_ip_bytes_val = c$orig$num_bytes_ip;   # Correct field: size_ip
    local resp_pkts_val = c$resp$num_pkts;
    local resp_ip_bytes_val = c$resp$num_bytes_ip;   # Correct field: size_ip

   

    # Create log record
    local rec: Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id_orig_h = c$id$orig_h,
        $id_resp_h = c$id$resp_h,
        $id_resp_p = id_resp_p,
        $proto = proto_val,
        $service = service_val,
        $duration = duration_val,
        $orig_bytes = orig_bytes_val,
        $resp_bytes = resp_bytes_val,
        $conn_state = conn_state_val,
        $missed_bytes = missed_bytes_val,
        $orig_pkts = orig_pkts_val,
        $orig_ip_bytes = orig_ip_bytes_val,
        $resp_pkts = resp_pkts_val,
        $resp_ip_bytes = resp_ip_bytes_val
    ];

    Log::write(IoTDetection::LOG, rec);
}
